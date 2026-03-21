// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/arq"
	"masterdnsvpn-go/internal/compression"
	"masterdnsvpn-go/internal/config"
	dnsCache "masterdnsvpn-go/internal/dnscache"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	domainMatcher "masterdnsvpn-go/internal/domainmatcher"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/fragmentstore"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
	SocksProto "masterdnsvpn-go/internal/socksproto"
	streamUtil "masterdnsvpn-go/internal/streamutil"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	mtuProbeModeRaw     = 0
	mtuProbeModeBase64  = 1
	mtuProbeCodeLength  = 4
	mtuProbeMetaLength  = mtuProbeCodeLength + 2
	mtuProbeUpMinSize   = 1 + mtuProbeCodeLength
	mtuProbeDownMinSize = mtuProbeUpMinSize + 2
	mtuProbeMinDownSize = 30
	mtuProbeMaxDownSize = 4096
	sessionAcceptSize   = 7
)

var preSessionPacketTypes = buildPreSessionPacketTypes()

type Server struct {
	cfg                      config.ServerConfig
	log                      *logger.Logger
	codec                    *security.Codec
	domainMatcher            *domainMatcher.Matcher
	sessions                 *sessionStore
	streams                  *streamStateStore
	streamOutbound           *streamOutboundStore
	deferredSession          *deferredSessionProcessor
	invalidCookieTracker     *invalidCookieTracker
	dnsCache                 *dnsCache.Store
	dnsResolveInflight       *dnsResolveInflightManager
	dnsUpstreamServers       []string
	dnsUpstreamBufferPool    sync.Pool
	dnsFragments             *fragmentstore.Store[dnsFragmentKey]
	socks5Fragments          *fragmentstore.Store[socks5FragmentKey]
	streamDataFragments      *fragmentstore.Store[streamDataFragmentKey]
	dnsFragmentTimeout       time.Duration
	resolveDNSQueryFn        func([]byte) ([]byte, error)
	dialStreamUpstreamFn     func(string, string, time.Duration) (net.Conn, error)
	uploadCompressionMask    uint8
	downloadCompressionMask  uint8
	dropLogIntervalNanos     int64
	invalidCookieWindow      time.Duration
	invalidCookieWindowNanos int64
	invalidCookieThreshold   int
	socksConnectTimeout      time.Duration
	useExternalSOCKS5        bool
	externalSOCKS5Address    string
	externalSOCKS5Auth       bool
	externalSOCKS5User       []byte
	externalSOCKS5Pass       []byte
	streamOutboundTTL        time.Duration
	streamOutboundMaxRetry   int
	mtuProbePayloadPool      sync.Pool
	mtuProbeFillPattern      [256]byte
	packetPool               sync.Pool
	droppedPackets           atomic.Uint64
	lastDropLogUnix          atomic.Int64
	pongNonce                atomic.Uint32
	invalidDropMode          atomic.Uint32
	arqWindowSize            int
}

type request struct {
	buf  []byte
	size int
	addr *net.UDPAddr
}

type postSessionValidation struct {
	record   *sessionRuntimeView
	response []byte
	ok       bool
}

func New(cfg config.ServerConfig, log *logger.Logger, codec *security.Codec) *Server {
	invalidCookieWindow := cfg.InvalidCookieWindow()
	if invalidCookieWindow <= 0 {
		invalidCookieWindow = 2 * time.Second
	}
	dnsFragmentTimeout := cfg.DNSFragmentAssemblyTimeout()
	if dnsFragmentTimeout <= 0 {
		dnsFragmentTimeout = 5 * time.Minute
	}
	dropLogInterval := cfg.DropLogInterval()
	if dropLogInterval <= 0 {
		dropLogInterval = 2 * time.Second
	}
	socksConnectTimeout := cfg.SOCKSConnectTimeout()
	if socksConnectTimeout <= 0 {
		socksConnectTimeout = 8 * time.Second
	}
	streamOutboundTTL := cfg.StreamOutboundTTL()
	if streamOutboundTTL <= 0 {
		streamOutboundTTL = 120 * time.Second
	}
	return &Server{
		cfg:                  cfg,
		arqWindowSize:        cfg.ARQWindowSize,
		log:                  log,
		codec:                codec,
		domainMatcher:        domainMatcher.New(cfg.Domain, cfg.MinVPNLabelLength),
		sessions:             newSessionStore(),
		streams:              newStreamStateStore(),
		streamOutbound:       newStreamOutboundStore(cfg.StreamOutboundWindow, cfg.StreamOutboundQueueLimit),
		deferredSession:      newDeferredSessionProcessor(cfg.DeferredSessionWorkers, cfg.DeferredSessionQueueLimit, log),
		invalidCookieTracker: newInvalidCookieTracker(),
		dnsCache: dnsCache.New(
			cfg.DNSCacheMaxRecords,
			time.Duration(cfg.DNSCacheTTLSeconds*float64(time.Second)),
			dnsFragmentTimeout,
		),
		dnsResolveInflight: newDNSResolveInflightManager(dnsFragmentTimeout),
		dnsUpstreamServers: append([]string(nil), cfg.DNSUpstreamServers...),
		dnsFragments:       fragmentstore.New[dnsFragmentKey](32),
		socks5Fragments:    fragmentstore.New[socks5FragmentKey](32),
		streamDataFragments: fragmentstore.New[streamDataFragmentKey](128),
		dnsFragmentTimeout: dnsFragmentTimeout,
		dnsUpstreamBufferPool: sync.Pool{
			New: func() any {
				return make([]byte, 65535)
			},
		},
		dialStreamUpstreamFn: func(network string, address string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout(network, address, timeout)
		},
		uploadCompressionMask:    buildCompressionMask(cfg.SupportedUploadCompressionTypes),
		downloadCompressionMask:  buildCompressionMask(cfg.SupportedDownloadCompressionTypes),
		dropLogIntervalNanos:     dropLogInterval.Nanoseconds(),
		invalidCookieWindow:      invalidCookieWindow,
		invalidCookieWindowNanos: invalidCookieWindow.Nanoseconds(),
		invalidCookieThreshold:   cfg.InvalidCookieErrorThreshold,
		socksConnectTimeout:      socksConnectTimeout,
		useExternalSOCKS5:        cfg.UseExternalSOCKS5,
		externalSOCKS5Address:    net.JoinHostPort(cfg.ForwardIP, strconv.Itoa(cfg.ForwardPort)),
		externalSOCKS5Auth:       cfg.SOCKS5Auth,
		externalSOCKS5User:       []byte(cfg.SOCKS5User),
		externalSOCKS5Pass:       []byte(cfg.SOCKS5Pass),
		streamOutboundTTL:        streamOutboundTTL,
		streamOutboundMaxRetry:   cfg.StreamOutboundMaxRetries,
		mtuProbePayloadPool: sync.Pool{
			New: func() any {
				return make([]byte, mtuProbeMaxDownSize)
			},
		},
		mtuProbeFillPattern: buildMTUProbeFillPattern(),
		packetPool: sync.Pool{
			New: func() any {
				return make([]byte, cfg.MaxPacketSize)
			},
		},
	}
}

func (s *Server) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP(s.cfg.UDPHost),
		Port: s.cfg.UDPPort,
	})

	if err != nil {
		return err
	}

	defer conn.Close()

	if err := conn.SetReadBuffer(s.cfg.SocketBufferSize); err != nil {
		s.log.Warnf("Ã¢Å¡Â Ã¯Â¸Â <yellow>UDP Read Buffer Setup Failed, <cyan>%v</cyan></yellow>", err)
	}

	if err := conn.SetWriteBuffer(s.cfg.SocketBufferSize); err != nil {
		s.log.Warnf("Ã¢Å¡Â Ã¯Â¸Â <yellow>UDP Write Buffer Setup Failed, <cyan>%v</cyan></yellow>", err)
	}

	s.log.Infof(
		"\U0001F4E1 <green>UDP Listener Ready, Addr: <cyan>%s</cyan>, Readers: <cyan>%d</cyan>, Workers: <cyan>%d</cyan>, Queue: <cyan>%d</cyan></green>",
		s.cfg.Address(),
		s.cfg.UDPReaders,
		s.cfg.DNSRequestWorkers,
		s.cfg.MaxConcurrentRequests,
	)

	reqCh := make(chan request, s.cfg.MaxConcurrentRequests)
	var workerWG sync.WaitGroup
	cleanupDone := make(chan struct{})

	go func() {
		defer close(cleanupDone)
		s.sessionCleanupLoop(runCtx)
	}()
	s.deferredSession.Start(runCtx)

	for i := range s.cfg.DNSRequestWorkers {
		workerWG.Add(1)
		go func(workerID int) {
			defer workerWG.Done()
			s.worker(runCtx, conn, reqCh, workerID)
		}(i + 1)
	}

	go func() {
		<-runCtx.Done()
		_ = conn.Close()
	}()

	readErrCh := make(chan error, s.cfg.UDPReaders)
	var readerWG sync.WaitGroup
	for i := range s.cfg.UDPReaders {
		readerWG.Add(1)
		go func(readerID int) {
			defer readerWG.Done()
			if err := s.readLoop(runCtx, conn, reqCh, readerID); err != nil {
				select {
				case readErrCh <- err:
				default:
				}
			}
		}(i + 1)
	}

	readerWG.Wait()
	close(reqCh)
	workerWG.Wait()
	cancel()
	<-cleanupDone

	if ctx.Err() != nil {
		return ctx.Err()
	}

	select {
	case err := <-readErrCh:
		return err
	default:
		return nil
	}
}

func (s *Server) sessionCleanupLoop(ctx context.Context) {
	interval := s.cfg.SessionCleanupInterval()
	if interval <= 0 {
		interval = 30 * time.Second
	}
	sessionTimeout := s.cfg.SessionTimeout()
	closedRetention := s.cfg.ClosedSessionRetention()
	invalidCookieWindow := s.invalidCookieWindow

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			expired := s.sessions.Cleanup(now, sessionTimeout, closedRetention)
			s.invalidCookieTracker.Cleanup(now, invalidCookieWindow)
			s.purgeDNSQueryFragments(now)
			s.purgeSOCKS5SynFragments(now)
			if len(expired) == 0 {
				continue
			}
			for _, sessionID := range expired {
				s.cleanupClosedSession(sessionID)
			}
			s.log.Infof(
				"\U0001F4E1 <green>Expired Sessions Cleaned, Count: <cyan>%d</cyan></green>",
				len(expired),
			)
		}
	}
}

func (s *Server) readLoop(ctx context.Context, conn *net.UDPConn, reqCh chan<- request, readerID int) error {
	for {
		buffer := s.packetPool.Get().([]byte)
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			s.packetPool.Put(buffer)

			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}

			s.log.Debugf(
				"\U0001F4A5 <yellow>UDP Read Error, Reader: <cyan>%d</cyan>, Error: <cyan>%v</cyan></yellow>",
				readerID,
				err,
			)
			return err
		}

		select {
		case reqCh <- request{buf: buffer, size: n, addr: addr}:
		case <-ctx.Done():
			s.packetPool.Put(buffer)
			return nil
		default:
			s.packetPool.Put(buffer)
			s.onDrop(addr)
		}
	}
}

func (s *Server) worker(ctx context.Context, conn *net.UDPConn, reqCh <-chan request, workerID int) {
	for {
		select {
		case <-ctx.Done():
			return
		case req, ok := <-reqCh:
			if !ok {
				return
			}

			response := s.safeHandlePacket(req.buf[:req.size])
			if len(response) != 0 {
				if _, err := conn.WriteToUDP(response, req.addr); err != nil {
					s.log.Debugf(
						"\U0001F4A5 <yellow>UDP Write Error, Worker: <cyan>%d</cyan>, Remote: <cyan>%v</cyan>, Error: <cyan>%v</cyan></yellow>",
						workerID,
						req.addr,
						err,
					)
				}
			}

			s.packetPool.Put(req.buf)
		}
	}
}

func (s *Server) safeHandlePacket(packet []byte) (response []byte) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if s.log != nil {
				s.log.Errorf(
					"\U0001F4A5 <red>Packet Handler Panic Recovered, <yellow>%v</yellow></red>",
					recovered,
				)
			}
			response = nil
		}
	}()
	return s.handlePacket(packet)
}

func (s *Server) handlePacket(packet []byte) []byte {
	parsed, err := DnsParser.ParseDNSRequestLite(packet)
	if err != nil {
		if errors.Is(err, DnsParser.ErrNotDNSRequest) || errors.Is(err, DnsParser.ErrPacketTooShort) {
			return nil
		}

		return buildNoDataResponse(packet)
	}

	if !parsed.HasQuestion {
		return buildNoDataResponse(packet)
	}

	decision := s.domainMatcher.Match(parsed)
	if decision.Action == domainMatcher.ActionProcess {
		return s.handleTunnelCandidate(packet, parsed, decision)
	}

	if decision.Action == domainMatcher.ActionFormatError || decision.Action == domainMatcher.ActionNoData {
		return buildNoDataResponseLite(packet, parsed)
	}

	return nil
}

func (s *Server) handleTunnelCandidate(packet []byte, parsed DnsParser.LitePacket, decision domainMatcher.Decision) []byte {
	vpnPacket, err := VpnProto.ParseInflatedFromLabels(decision.Labels, s.codec)
	if err != nil {
		return buildNoDataResponseLite(packet, parsed)
	}

	if vpnPacket.PacketType == Enums.PACKET_SESSION_CLOSE {
		s.handleSessionCloseNotice(vpnPacket, time.Now())
		return nil
	}

	if !isPreSessionRequestType(vpnPacket.PacketType) {
		validation := s.validatePostSessionPacket(packet, decision.RequestName, vpnPacket)
		if !validation.ok {
			return validation.response
		}

		if !s.handlePostSessionPacket(decision, vpnPacket, validation.record) {
			return buildNoDataResponseLite(packet, parsed)
		}

		return s.serveQueuedOrPong(packet, decision.RequestName, validation.record, time.Now())
	}

	switch vpnPacket.PacketType {
	case Enums.PACKET_MTU_UP_REQ:
		return s.handleMTUUpRequest(packet, parsed, decision, vpnPacket)
	case Enums.PACKET_MTU_DOWN_REQ:
		return s.handleMTUDownRequest(packet, parsed, decision, vpnPacket)
	case Enums.PACKET_SESSION_INIT:
		return s.handleSessionInitRequest(packet, decision, vpnPacket)
	default:
		return buildNoDataResponseLite(packet, parsed)
	}
}

func (s *Server) handlePostSessionPacket(decision domainMatcher.Decision, vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if handled := s.handleClosedStreamPacket(vpnPacket); handled {
		return true
	}

	switch vpnPacket.PacketType {
	case Enums.PACKET_PACKED_CONTROL_BLOCKS:
		return s.handlePackedControlBlocksRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_PING:
		return s.handlePingRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_RESEND:
		return s.handleStreamDataRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_DATA_ACK, Enums.PACKET_STREAM_FIN_ACK, Enums.PACKET_STREAM_RST_ACK, Enums.PACKET_STREAM_SYN_ACK:
		return s.handleStreamAckPacket(vpnPacket, sessionRecord)
	case Enums.PACKET_DNS_QUERY_REQ:
		return s.handleDNSQueryRequest(decision, vpnPacket, sessionRecord)
	case Enums.PACKET_DNS_QUERY_RES_ACK:
		return s.handleDNSQueryResponseAck(vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_SYN:
		return s.handleStreamSynRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_SOCKS5_SYN:
		return s.handleSOCKS5SynRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_FIN:
		return s.handleStreamFinRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_RST:
		return s.handleStreamRSTRequest(vpnPacket, sessionRecord)
	default:
		return false
	}
}

func (s *Server) handleClosedStreamPacket(vpnPacket VpnProto.Packet) bool {
	if s == nil || vpnPacket.StreamID == 0 || !isClosedStreamAwarePacketType(vpnPacket.PacketType) {
		return false
	}
	response, handled := s.streams.HandleClosedPacket(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.PacketType, vpnPacket.SequenceNum, time.Now())
	if !handled {
		return false
	}
	if response.PacketType != 0 {
		_ = s.queueSessionPacket(vpnPacket.SessionID, response)
	}
	return true
}

func isClosedStreamAwarePacketType(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_STREAM_SYN,
		Enums.PACKET_SOCKS5_SYN,
		Enums.PACKET_STREAM_DATA,
		Enums.PACKET_STREAM_RESEND,
		Enums.PACKET_STREAM_DATA_ACK,
		Enums.PACKET_STREAM_FIN,
		Enums.PACKET_STREAM_RST:
		return true
	default:
		return false
	}
}

func (s *Server) validatePostSessionPacket(questionPacket []byte, requestName string, vpnPacket VpnProto.Packet) postSessionValidation {
	now := time.Now()
	validation := s.sessions.ValidateAndTouch(vpnPacket.SessionID, vpnPacket.SessionCookie, now)
	if validation.Valid {
		if validation.Active != nil {
			s.streamOutbound.ConfigureSession(validation.Active.ID, validation.Active.MaxPackedBlocks)
		}
		return postSessionValidation{
			record: validation.Active,
			ok:     true,
		}
	}

	if !validation.Known {
		mode := s.nextUnknownInvalidDropMode()
		s.logInvalidSessionDrop("unknown session", vpnPacket.SessionID, vpnPacket.SessionCookie, 0, mode)
		return postSessionValidation{
			response: s.buildInvalidSessionErrorResponse(questionPacket, requestName, vpnPacket.SessionID, mode),
		}
	}

	if validation.Lookup.State == sessionLookupClosed {
		s.logInvalidSessionDrop("recently closed session", vpnPacket.SessionID, vpnPacket.SessionCookie, validation.Lookup.Cookie, validation.Lookup.ResponseMode)
		return postSessionValidation{
			response: s.buildInvalidSessionErrorResponse(questionPacket, requestName, vpnPacket.SessionID, validation.Lookup.ResponseMode),
		}
	}

	if !s.invalidCookieTracker.Note(
		vpnPacket.SessionID,
		validation.Lookup,
		validation.Known,
		vpnPacket.SessionCookie,
		now.UnixNano(),
		s.invalidCookieWindowNanos,
		s.invalidCookieThreshold,
	) {
		return postSessionValidation{}
	}

	if s.debugLoggingEnabled() {
		s.logInvalidSessionThreshold(vpnPacket.SessionID, vpnPacket.SessionCookie, validation.Lookup, validation.Known)
	}
	s.logInvalidSessionDrop("invalid cookie threshold", vpnPacket.SessionID, vpnPacket.SessionCookie, validation.Lookup.Cookie, validation.Lookup.ResponseMode)

	return postSessionValidation{
		response: s.buildInvalidSessionErrorResponse(questionPacket, requestName, vpnPacket.SessionID, validation.Lookup.ResponseMode),
	}
}

func (s *Server) handleSessionCloseNotice(vpnPacket VpnProto.Packet, now time.Time) {
	if s == nil || vpnPacket.SessionID == 0 {
		return
	}

	lookup, known := s.sessions.Lookup(vpnPacket.SessionID)
	if !known || lookup.State != sessionLookupActive || lookup.Cookie != vpnPacket.SessionCookie {
		return
	}
	if !s.sessions.Close(vpnPacket.SessionID, now, s.cfg.ClosedSessionRetention()) {
		return
	}

	s.cleanupClosedSession(vpnPacket.SessionID)
	if s.log != nil {
		s.log.Infof(
			"\U0001F6AA <green>Session Closed By Client, Session: <cyan>%d</cyan></green>",
			vpnPacket.SessionID,
		)
	}
}

func (s *Server) logInvalidSessionThreshold(sessionID uint8, receivedCookie uint8, lookup sessionLookupResult, known bool) {
	if !known {
		s.log.Debugf(
			"\U0001F9D7 <yellow>Unknown Session Cookie Threshold Reached, Session: <cyan>%d</cyan>, Received: <cyan>%d</cyan></yellow>",
			sessionID,
			receivedCookie,
		)
		return
	}

	if lookup.State == sessionLookupClosed {
		s.log.Debugf(
			"\U0001F9D7 <yellow>Stale Closed Session Cookie Threshold Reached, Session: <cyan>%d</cyan>, Expected: <cyan>%d</cyan>, Received: <cyan>%d</cyan></yellow>",
			sessionID,
			lookup.Cookie,
			receivedCookie,
		)
		return
	}

	s.log.Debugf(
		"\U0001F9D7 <yellow>Invalid Session Cookie Threshold Reached, Session: <cyan>%d</cyan>, Expected: <cyan>%d</cyan>, Received: <cyan>%d</cyan></yellow>",
		sessionID,
		lookup.Cookie,
		receivedCookie,
	)
}

func (s *Server) logInvalidSessionDrop(reason string, sessionID uint8, receivedCookie uint8, expectedCookie uint8, responseMode uint8) {
	if !s.debugLoggingEnabled() {
		return
	}
	if expectedCookie == 0 {
		s.log.Debugf(
			"ðŸª‚ <yellow>Sending Session Drop</yellow> <magenta>|</magenta> <blue>Reason</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Received</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Mode</blue>: <cyan>%s</cyan>",
			reason,
			sessionID,
			receivedCookie,
			sessionResponseModeName(responseMode),
		)
		return
	}
	s.log.Debugf(
		"ðŸª‚ <yellow>Sending Session Drop</yellow> <magenta>|</magenta> <blue>Reason</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Expected</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Received</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Mode</blue>: <cyan>%s</cyan>",
		reason,
		sessionID,
		expectedCookie,
		receivedCookie,
		sessionResponseModeName(responseMode),
	)
}

func (s *Server) debugLoggingEnabled() bool {
	return s != nil && s.log != nil && s.log.Enabled(logger.LevelDebug)
}

func buildNoDataResponse(packet []byte) []byte {
	response, err := DnsParser.BuildEmptyNoErrorResponse(packet)
	if err != nil {
		return nil
	}
	return response
}

func buildNoDataResponseLite(packet []byte, parsed DnsParser.LitePacket) []byte {
	response, err := DnsParser.BuildEmptyNoErrorResponseFromLite(packet, parsed)
	if err != nil {
		return nil
	}
	return response
}

func (s *Server) buildInvalidSessionErrorResponse(questionPacket []byte, requestName string, sessionID uint8, responseMode uint8) []byte {
	payload := s.nextInvalidDropPayload()
	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, requestName, VpnProto.Packet{
		SessionID:  sessionID,
		PacketType: Enums.PACKET_ERROR_DROP,
		Payload:    payload[:],
	}, responseMode == mtuProbeModeBase64)
	if err != nil {
		return nil
	}
	return response
}

func (s *Server) buildSessionBusyResponse(questionPacket []byte, requestName string, responseMode uint8, verifyCode []byte) []byte {
	if len(verifyCode) < mtuProbeCodeLength {
		return nil
	}
	var payload [mtuProbeCodeLength]byte
	copy(payload[:], verifyCode[:mtuProbeCodeLength])
	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, requestName, VpnProto.Packet{
		SessionID:  0,
		PacketType: Enums.PACKET_SESSION_BUSY,
		Payload:    payload[:],
	}, responseMode == mtuProbeModeBase64)
	if err != nil {
		return nil
	}
	return response
}

func (s *Server) buildSessionVPNResponse(questionPacket []byte, requestName string, record *sessionRuntimeView, packet VpnProto.Packet) []byte {
	if record == nil {
		return nil
	}
	packet.SessionID = record.ID
	packet.SessionCookie = record.Cookie
	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, requestName, packet, record.ResponseBase64)
	if err != nil {
		return nil
	}
	return response
}

func (s *Server) queueSessionPacket(sessionID uint8, packet VpnProto.Packet) bool {
	if s == nil || sessionID == 0 || !s.sessions.HasActive(sessionID) {
		return false
	}
	streamExists := packet.StreamID != 0 && s.streams.Exists(sessionID, packet.StreamID)
	target, ok := arq.QueueTargetForPacket(streamExists, packet.PacketType, packet.StreamID)
	if !ok {
		return false
	}
	return s.streamOutbound.Enqueue(sessionID, target, packet)
}

func (s *Server) queueMainSessionPacket(sessionID uint8, packet VpnProto.Packet) bool {
	if s == nil || sessionID == 0 || !s.sessions.HasActive(sessionID) {
		return false
	}
	return s.streamOutbound.Enqueue(sessionID, arq.QueueTargetMain, packet)
}

func (s *Server) cleanupClosedSession(sessionID uint8) {
	if s == nil || sessionID == 0 {
		return
	}
	s.streams.RemoveSession(sessionID)
	s.streamOutbound.RemoveSession(sessionID)
	s.deferredSession.RemoveSession(sessionID)
	s.removeDNSQueryFragmentsForSession(sessionID)
	s.removeSOCKS5SynFragmentsForSession(sessionID)
	s.removeStreamDataFragmentsForSession(sessionID)
}

func (s *Server) serveQueuedOrPong(questionPacket []byte, requestName string, sessionRecord *sessionRuntimeView, now time.Time) []byte {
	if sessionRecord == nil {
		return nil
	}
	sessionID := sessionRecord.ID

	s.expireStalledOutboundStreams(sessionID, now)
	if queued := s.streamOutbound.NextDetailed(sessionID, now); queued.HasPacket {
		if s.log != nil {
			sendKind := "first-send"
			if queued.IsRetry {
				sendKind = "retry"
			}
			stats := s.streamOutbound.SessionStats(sessionID)
			s.log.Debugf(
				"\U0001F4E4 <blue>Serving Queued Packet</blue> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Packet</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Bytes</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Mode</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Retry</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Pending</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Queued</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Window</blue>: <cyan>%d</cyan>",
				sessionID,
				Enums.PacketTypeName(queued.Packet.PacketType),
				queued.Packet.StreamID,
				queued.Packet.SequenceNum,
				len(queued.Packet.Payload),
				sendKind,
				queued.RetryCount,
				stats.Pending,
				stats.SchedulerPending,
				stats.Window,
			)
		}
		resp := s.buildSessionVPNResponse(questionPacket, requestName, sessionRecord, queued.Packet)
		arq.FreePayload(queued.Packet.Payload)
		return resp
	}

	payload := s.nextPongPayload()

	return s.buildSessionVPNResponse(questionPacket, requestName, sessionRecord, VpnProto.Packet{
		PacketType: Enums.PACKET_PONG,
		Payload:    payload[:],
	})
}

func (s *Server) nextPongPayload() [7]byte {
	var payload [7]byte
	payload[0] = 'P'
	payload[1] = 'O'
	payload[2] = ':'

	nonce := s.pongNonce.Add(1)
	nonce ^= nonce << 13
	nonce ^= nonce >> 17
	nonce ^= nonce << 5
	binary.BigEndian.PutUint32(payload[3:], nonce)

	return payload
}

func (s *Server) nextInvalidDropPayload() [8]byte {
	var payload [8]byte
	payload[0] = 'I'
	payload[1] = 'N'
	payload[2] = 'V'

	nonce := s.pongNonce.Add(1)
	nonce ^= nonce << 13
	nonce ^= nonce >> 17
	nonce ^= nonce << 5
	binary.BigEndian.PutUint32(payload[3:7], nonce)
	payload[7] = byte(nonce)
	return payload
}

func (s *Server) nextUnknownInvalidDropMode() uint8 {
	if s == nil {
		return mtuProbeModeRaw
	}
	if s.invalidDropMode.Add(1)&1 == 0 {
		return mtuProbeModeRaw
	}
	return mtuProbeModeBase64
}

func deferredSessionLaneForPacket(packet VpnProto.Packet) deferredSessionLane {
	return deferredSessionLane{
		sessionID: packet.SessionID,
		streamID:  packet.StreamID,
	}
}

func isDeferredPostSessionPacketType(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_DNS_QUERY_REQ,
		Enums.PACKET_STREAM_SYN,
		Enums.PACKET_SOCKS5_SYN,
		Enums.PACKET_STREAM_DATA,
		Enums.PACKET_STREAM_RESEND:
		return true
	default:
		return false
	}
}

func (s *Server) dispatchDeferredSessionPacket(packet VpnProto.Packet, run func()) bool {
	if s == nil || s.deferredSession == nil || !isDeferredPostSessionPacketType(packet.PacketType) {
		return false
	}
	return s.deferredSession.Enqueue(deferredSessionLaneForPacket(packet), run)
}

func isPreSessionRequestType(packetType uint8) bool {
	return preSessionPacketTypes[packetType]
}

func buildPreSessionPacketTypes() [256]bool {
	var values [256]bool
	values[Enums.PACKET_SESSION_INIT] = true
	values[Enums.PACKET_MTU_UP_REQ] = true
	values[Enums.PACKET_MTU_DOWN_REQ] = true
	return values
}

func (s *Server) handleSessionInitRequest(questionPacket []byte, decision domainMatcher.Decision, vpnPacket VpnProto.Packet) []byte {
	if vpnPacket.SessionID != 0 || len(vpnPacket.Payload) != sessionInitDataSize {
		return nil
	}

	requestedUpload, requestedDownload := compression.SplitPair(vpnPacket.Payload[1])
	resolvedUpload := resolveCompressionType(requestedUpload, s.uploadCompressionMask)
	resolvedDownload := resolveCompressionType(requestedDownload, s.downloadCompressionMask)

	record, reused, err := s.sessions.findOrCreate(
		vpnPacket.Payload,
		resolvedUpload,
		resolvedDownload,
		s.cfg.MaxPacketsPerBatch,
	)

	if err != nil {
		if err == ErrSessionTableFull {
			if s.log != nil {
				s.log.Errorf(
					"\U0001F6AB <red>Session Table Full Request: <cyan>SESSION_INIT</cyan>, Domain: <cyan>%s</cyan></red>",
					decision.RequestName,
				)
			}
			return s.buildSessionBusyResponse(questionPacket, decision.RequestName, vpnPacket.Payload[0], vpnPacket.Payload[6:10])
		}
		return nil
	}
	if record == nil {
		return nil
	}
	s.streamOutbound.ConfigureSession(record.ID, record.MaxPackedBlocks)

	if !reused && s.log != nil {
		s.log.Infof(
			"\U0001F9DD <green>Session Created, ID: <cyan>%d</cyan>, Mode: <cyan>%s</cyan>, Upload Compression: <cyan>%s</cyan>, Download Compression: <cyan>%s</cyan>, Client Upload MTU: <cyan>%d</cyan>, Client Download MTU: <cyan>%d</cyan>, Max Packed Blocks: <cyan>%d</cyan></green>",
			record.ID,
			sessionResponseModeName(record.ResponseMode),
			compression.TypeName(record.UploadCompression),
			compression.TypeName(record.DownloadCompression),
			record.UploadMTU,
			record.DownloadMTU,
			record.MaxPackedBlocks,
		)
	}

	var responsePayload [sessionAcceptSize]byte
	responsePayload[0] = record.ID
	responsePayload[1] = record.Cookie
	responsePayload[2] = compression.PackPair(record.UploadCompression, record.DownloadCompression)
	copy(responsePayload[3:], record.VerifyCode[:])

	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, decision.RequestName, VpnProto.Packet{
		SessionID:  0,
		PacketType: Enums.PACKET_SESSION_ACCEPT,
		Payload:    responsePayload[:],
	}, record.ResponseMode == mtuProbeModeBase64)

	if err != nil {
		return nil
	}

	return response
}

func sessionResponseModeName(mode uint8) string {
	if mode == mtuProbeModeBase64 {
		return "BASE64"
	}
	return "RAW (Bytes)"
}

func buildCompressionMask(values []int) uint8 {
	var mask uint8 = 1 << compression.TypeOff
	for _, value := range values {
		if value < compression.TypeOff || value > compression.TypeZLIB || !compression.IsTypeAvailable(uint8(value)) {
			continue
		}
		mask |= 1 << uint8(value)
	}
	return mask
}

func resolveCompressionType(requested uint8, allowedMask uint8) uint8 {
	if requested <= compression.TypeZLIB && allowedMask&(1<<requested) != 0 {
		return requested
	}
	return compression.TypeOff
}

func (s *Server) onDrop(addr *net.UDPAddr) {
	total := s.droppedPackets.Add(1)

	now := logger.NowUnixNano()
	last := s.lastDropLogUnix.Load()
	interval := s.dropLogIntervalNanos
	if interval <= 0 {
		interval = 2_000_000_000
	}
	if now-last < interval {
		return
	}
	if !s.lastDropLogUnix.CompareAndSwap(last, now) {
		return
	}

	s.log.Warnf(
		"\U0001F6A8 <yellow>Request Queue Overloaded</yellow> <magenta>|</magenta> <blue>Dropped</blue>: <magenta>%d</magenta> <magenta>|</magenta> <blue>Remote</blue>: <cyan>%v</cyan>",
		total,
		addr,
	)
}

func (s *Server) handleMTUUpRequest(questionPacket []byte, _ DnsParser.LitePacket, decision domainMatcher.Decision, vpnPacket VpnProto.Packet) []byte {
	if len(vpnPacket.Payload) < mtuProbeUpMinSize {
		return nil
	}

	baseEncode, ok := parseMTUProbeBaseEncoding(vpnPacket.Payload[0])
	if !ok {
		return nil
	}

	responsePayload := buildMTUProbeMetaPayload(vpnPacket.Payload[1:mtuProbeUpMinSize], len(vpnPacket.Payload))
	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, decision.RequestName, VpnProto.Packet{
		SessionID:  vpnPacket.SessionID,
		PacketType: Enums.PACKET_MTU_UP_RES,
		Payload:    responsePayload[:],
	}, baseEncode)

	if err != nil {
		return nil
	}

	return response
}

func (s *Server) handleMTUDownRequest(questionPacket []byte, _ DnsParser.LitePacket, decision domainMatcher.Decision, vpnPacket VpnProto.Packet) []byte {
	if len(vpnPacket.Payload) < mtuProbeDownMinSize {
		return nil
	}

	baseEncode, ok := parseMTUProbeBaseEncoding(vpnPacket.Payload[0])
	if !ok {
		return nil
	}
	downloadSize := int(binary.BigEndian.Uint16(vpnPacket.Payload[mtuProbeUpMinSize:mtuProbeDownMinSize]))
	if downloadSize < mtuProbeMinDownSize || downloadSize > mtuProbeMaxDownSize {
		return nil
	}

	payloadBuffer := s.mtuProbePayloadPool.Get().([]byte)
	defer s.mtuProbePayloadPool.Put(payloadBuffer)
	payload := payloadBuffer[:downloadSize]
	copy(payload[:mtuProbeCodeLength], vpnPacket.Payload[1:mtuProbeUpMinSize])
	binary.BigEndian.PutUint16(payload[mtuProbeCodeLength:], uint16(downloadSize))
	if downloadSize > mtuProbeMetaLength {
		fillMTUProbeBytes(payload[mtuProbeMetaLength:], s.mtuProbeFillPattern[:])
	}

	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, decision.RequestName, VpnProto.Packet{
		SessionID:      vpnPacket.SessionID,
		PacketType:     Enums.PACKET_MTU_DOWN_RES,
		StreamID:       vpnPacket.StreamID,
		SequenceNum:    vpnPacket.SequenceNum,
		FragmentID:     vpnPacket.FragmentID,
		TotalFragments: vpnPacket.TotalFragments,
		Payload:        payload,
	}, baseEncode)

	if err != nil {
		return nil
	}

	return response
}

func parseMTUProbeBaseEncoding(mode uint8) (bool, bool) {
	switch mode {
	case mtuProbeModeRaw:
		return false, true
	case mtuProbeModeBase64:
		return true, true
	default:
		return false, false
	}
}

func buildMTUProbeMetaPayload(probeCode []byte, payloadLen int) [mtuProbeMetaLength]byte {
	var payload [mtuProbeMetaLength]byte
	copy(payload[:mtuProbeCodeLength], probeCode)
	binary.BigEndian.PutUint16(payload[mtuProbeCodeLength:], uint16(payloadLen))
	return payload
}

func buildMTUProbeFillPattern() [256]byte {
	var pattern [256]byte
	var state uint32 = 0x9E3779B9
	for i := range pattern {
		state = state*1664525 + 1013904223
		pattern[i] = byte(state >> 24)
	}
	return pattern
}

func fillMTUProbeBytes(dst []byte, pattern []byte) {
	if len(dst) == 0 || len(pattern) == 0 {
		return
	}

	copied := copy(dst, pattern)
	for copied < len(dst) {
		copied += copy(dst[copied:], dst[:copied])
	}
}

func (s *Server) handlePingRequest(_ VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	return sessionRecord != nil
}

func (s *Server) handlePackedControlBlocksRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if sessionRecord == nil || len(vpnPacket.Payload) < arq.PackedControlBlockSize {
		return false
	}

	handled := false
	arq.ForEachPackedControlBlock(vpnPacket.Payload, func(packetType uint8, streamID uint16, sequenceNum uint16, fragmentID uint8, totalFragments uint8) bool {
		if packetType == Enums.PACKET_PACKED_CONTROL_BLOCKS {
			return true
		}
		block := VpnProto.Packet{
			SessionID:      vpnPacket.SessionID,
			SessionCookie:  vpnPacket.SessionCookie,
			PacketType:     packetType,
			StreamID:       streamID,
			HasStreamID:    streamID != 0,
			SequenceNum:    sequenceNum,
			HasSequenceNum: sequenceNum != 0,
			FragmentID:     fragmentID,
			TotalFragments: totalFragments,
		}
		if s.handlePackedPostSessionBlock(block, sessionRecord) {
			handled = true
		}
		return true
	})
	return handled
}

func (s *Server) handlePackedPostSessionBlock(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	switch vpnPacket.PacketType {
	case Enums.PACKET_PING:
		return s.handlePingRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_DNS_QUERY_RES_ACK:
		return s.handleDNSQueryResponseAck(vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_DATA_ACK, Enums.PACKET_STREAM_FIN_ACK, Enums.PACKET_STREAM_RST_ACK, Enums.PACKET_STREAM_SYN_ACK:
		return s.handleStreamAckPacket(vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_FIN:
		return s.handleStreamFinRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_RST:
		return s.handleStreamRSTRequest(vpnPacket, sessionRecord)
	default:
		return false
	}
}

func (s *Server) processDeferredDNSQuery(sessionID uint8, sequenceNum uint16, downloadCompression uint8, downloadMTUBytes int, assembledQuery []byte) {
	if !s.sessions.HasActive(sessionID) {
		return
	}
	rawResponse := s.buildDNSQueryResponsePayload(assembledQuery, sessionID, sequenceNum)
	if len(rawResponse) == 0 {
		return
	}
	fragments := s.fragmentDNSResponsePayload(rawResponse, downloadMTUBytes)
	if len(fragments) == 0 {
		return
	}
	totalFragments := uint8(len(fragments))
	for fragmentID, fragmentPayload := range fragments {
		_ = s.queueMainSessionPacket(sessionID, VpnProto.Packet{
			PacketType:      Enums.PACKET_DNS_QUERY_RES,
			StreamID:        0,
			SequenceNum:     sequenceNum,
			FragmentID:      uint8(fragmentID),
			TotalFragments:  totalFragments,
			CompressionType: downloadCompression,
			Payload:         fragmentPayload,
		})
	}
}

func (s *Server) processDeferredStreamSyn(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) {
	if !s.sessions.HasActive(vpnPacket.SessionID) {
		return
	}
	now := time.Now()
	if VpnProto.IsTCPForwardSynPayload(vpnPacket.Payload) {
		if s.cfg.ForwardIP == "" || s.cfg.ForwardPort <= 0 {
			_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
				PacketType:  Enums.PACKET_STREAM_RST,
				StreamID:    vpnPacket.StreamID,
				SequenceNum: vpnPacket.SequenceNum,
			})
			return
		}
		if existing, ok := s.streams.Lookup(vpnPacket.SessionID, vpnPacket.StreamID); ok && existing != nil && existing.Connected && existing.TargetHost == s.cfg.ForwardIP && existing.TargetPort == uint16(s.cfg.ForwardPort) {
			if s.log != nil {
				s.log.Debugf("🧦 <green>STREAM_SYN Fast-Ack (Existing), Session: <cyan>%d</cyan> | Stream: <cyan>%d</cyan></green>", vpnPacket.SessionID, vpnPacket.StreamID)
			}
			_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
				PacketType:     Enums.PACKET_STREAM_SYN_ACK,
				StreamID:       vpnPacket.StreamID,
				SequenceNum:    vpnPacket.SequenceNum,
				FragmentID:     0,
				TotalFragments: 0,
			})
			return
		}
		if s.log != nil {
			s.log.Debugf("🧦 <blue>STREAM_SYN Processing, Session: <cyan>%d</cyan> | Stream: <cyan>%d</cyan> | Forwarding</blue>", vpnPacket.SessionID, vpnPacket.StreamID)
		}
		s.streams.EnsureOpen(vpnPacket.SessionID, vpnPacket.StreamID, s.arqWindowSize, now)
		upstreamConn, err := s.dialSOCKSStreamTarget(s.cfg.ForwardIP, uint16(s.cfg.ForwardPort), nil)
		if err != nil {
			_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
				PacketType:  Enums.PACKET_STREAM_RST,
				StreamID:    vpnPacket.StreamID,
				SequenceNum: vpnPacket.SequenceNum,
			})
			return
		}
		record, ok := s.streams.AttachUpstream(vpnPacket.SessionID, vpnPacket.StreamID, s.cfg.ForwardIP, uint16(s.cfg.ForwardPort), upstreamConn, now)
		if !ok || record == nil {
			streamUtil.SafeClose(upstreamConn)
			_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
				PacketType:  Enums.PACKET_STREAM_RST,
				StreamID:    vpnPacket.StreamID,
				SequenceNum: vpnPacket.SequenceNum,
			})
			return
		}
		s.startStreamUpstreamReadLoop(vpnPacket.SessionID, vpnPacket.StreamID, upstreamConn, sessionRecord.DownloadCompression, sessionRecord.StreamReadBufferSize)
	} else {
		s.streams.EnsureOpen(vpnPacket.SessionID, vpnPacket.StreamID, s.arqWindowSize, now)
	}

	_, _ = s.streams.Touch(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, now)
	_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
		PacketType:     Enums.PACKET_STREAM_SYN_ACK,
		StreamID:       vpnPacket.StreamID,
		SequenceNum:    vpnPacket.SequenceNum,
		FragmentID:     0,
		TotalFragments: 0,
	})
}

func (s *Server) processDeferredSOCKS5Syn(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) {
	if !s.sessions.HasActive(vpnPacket.SessionID) {
		return
	}
	now := time.Now()
	if s.log != nil {
		s.log.Debugf(
			"🧦 <blue>Processing SOCKS5 SYN</blue> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Frag</blue>: <cyan>%d/%d</cyan>",
			vpnPacket.SessionID,
			vpnPacket.StreamID,
			vpnPacket.FragmentID+1,
			max(1, int(vpnPacket.TotalFragments)),
		)
	}
	totalFragments := vpnPacket.TotalFragments
	if totalFragments == 0 {
		totalFragments = 1
	}
	assembledTarget, ready, completed := s.collectSOCKS5SynFragments(
		vpnPacket.SessionID,
		vpnPacket.StreamID,
		vpnPacket.SequenceNum,
		vpnPacket.Payload,
		vpnPacket.FragmentID,
		totalFragments,
		now,
	)
	if completed {
		_, _ = s.streams.Touch(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, now)
		_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
			PacketType:     Enums.PACKET_SOCKS5_SYN_ACK,
			StreamID:       vpnPacket.StreamID,
			SequenceNum:    vpnPacket.SequenceNum,
			FragmentID:     vpnPacket.FragmentID,
			TotalFragments: totalFragments,
		})
		return
	}
	if !ready {
		_, _ = s.streams.Touch(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, now)
		_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
			PacketType:     Enums.PACKET_SOCKS5_SYN_ACK,
			StreamID:       vpnPacket.StreamID,
			SequenceNum:    vpnPacket.SequenceNum,
			FragmentID:     vpnPacket.FragmentID,
			TotalFragments: totalFragments,
		})
		return
	}

	target, err := SocksProto.ParseTargetPayload(assembledTarget)
	if err != nil {
		packetType := uint8(Enums.PACKET_SOCKS5_CONNECT_FAIL)
		if errors.Is(err, SocksProto.ErrUnsupportedAddressType) || errors.Is(err, SocksProto.ErrInvalidDomainLength) {
			packetType = uint8(Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED)
		}
		_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
			PacketType:  packetType,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: vpnPacket.SequenceNum,
		})
		return
	}

	existingRecord, ok := s.streams.Lookup(vpnPacket.SessionID, vpnPacket.StreamID)
	if !ok || existingRecord == nil {
		_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
			PacketType:  Enums.PACKET_SOCKS5_CONNECT_FAIL,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: vpnPacket.SequenceNum,
		})
		return
	}
	if existingRecord.Connected && existingRecord.TargetHost == target.Host && existingRecord.TargetPort == target.Port {
		if s.log != nil {
			s.log.Debugf("🧦 <green>SOCKS5_SYN Fast-Ack (Existing), Session: <cyan>%d</cyan> | Stream: <cyan>%d</cyan></green>", vpnPacket.SessionID, vpnPacket.StreamID)
		}
		_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
			PacketType:  Enums.PACKET_SOCKS5_SYN_ACK,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: vpnPacket.SequenceNum,
		})
		return
	}
	if existingRecord.Connected && (existingRecord.TargetHost != target.Host || existingRecord.TargetPort != target.Port) {
		_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
			PacketType:  Enums.PACKET_SOCKS5_CONNECT_FAIL,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: vpnPacket.SequenceNum,
		})
		return
	}

	upstreamConn, err := s.dialSOCKSStreamTarget(target.Host, target.Port, assembledTarget)
	if err != nil {
		packetType := s.mapSOCKSConnectError(err)
		if s.log != nil {
			s.log.Debugf(
				"\U0001F9E6 <yellow>SOCKS5 Upstream Connect Failed</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Target</blue>: <cyan>%s:%d</cyan> <magenta>|</magenta> <blue>Packet</blue>: <yellow>%s</yellow> <magenta>|</magenta> <cyan>%v</cyan>",
				vpnPacket.SessionID,
				vpnPacket.StreamID,
				target.Host,
				target.Port,
				Enums.PacketTypeName(packetType),
				err,
			)
		}
		_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
			PacketType:  packetType,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: vpnPacket.SequenceNum,
		})
		return
	}

	record, ok := s.streams.AttachUpstream(vpnPacket.SessionID, vpnPacket.StreamID, target.Host, target.Port, upstreamConn, now)
	if !ok || record == nil {
		streamUtil.SafeClose(upstreamConn)
		_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
			PacketType:  Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: vpnPacket.SequenceNum,
		})
		return
	}
	s.startStreamUpstreamReadLoop(vpnPacket.SessionID, vpnPacket.StreamID, upstreamConn, sessionRecord.DownloadCompression, sessionRecord.StreamReadBufferSize)

	if s.log != nil {
		s.log.Debugf(
			"\U0001F9E6 <green>SOCKS5 Stream Prepared</green> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Target</blue>: <cyan>%s:%d</cyan>",
			record.SessionID,
			record.StreamID,
			record.TargetHost,
			record.TargetPort,
		)
	}

	_, _ = s.streams.Touch(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, now)
	_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
		PacketType:  Enums.PACKET_SOCKS5_SYN_ACK,
		StreamID:    vpnPacket.StreamID,
		SequenceNum: vpnPacket.SequenceNum,
	})
}

func (s *Server) processDeferredStreamData(vpnPacket VpnProto.Packet) {
	if !s.sessions.HasActive(vpnPacket.SessionID) {
		return
	}
	now := time.Now()
	assembledPayload, ready, completed := s.collectStreamDataFragments(vpnPacket, now)
	totalFragments := vpnPacket.TotalFragments
	if totalFragments == 0 {
		totalFragments = 1
	}
	if completed {
		_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
			PacketType:  Enums.PACKET_STREAM_DATA_ACK,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: vpnPacket.SequenceNum,
		})
		if s.log != nil {
			s.log.Debugf(
				"\u267B <yellow>Inbound Stream Data Fragment Replay</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan>",
				vpnPacket.SessionID,
				vpnPacket.StreamID,
				vpnPacket.SequenceNum,
			)
		}
		return
	}
	if !ready {
		if s.log != nil {
			s.log.Debugf(
				"\U0001F9E9 <blue>Collecting Stream Data Fragments</blue> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Fragment</blue>: <cyan>%d/%d</cyan> <magenta>|</magenta> <blue>Bytes</blue>: <cyan>%d</cyan>",
				vpnPacket.SessionID,
				vpnPacket.StreamID,
				vpnPacket.SequenceNum,
				vpnPacket.FragmentID+1,
				totalFragments,
				len(vpnPacket.Payload),
			)
		}
		return
	}
	streamRecord, decision, ok := s.streams.ReceiveInboundData(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, assembledPayload, now)
	if !ok || streamRecord == nil {
		_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
			PacketType:  Enums.PACKET_STREAM_RST,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: 0,
		})
		return
	}

	switch streamRecord.State {
	case Enums.STREAM_STATE_OPEN, Enums.STREAM_STATE_HALF_CLOSED_LOCAL, Enums.STREAM_STATE_HALF_CLOSED_REMOTE, Enums.STREAM_STATE_DRAINING, Enums.STREAM_STATE_CLOSING, Enums.STREAM_STATE_TIME_WAIT:
		if s.log != nil {
			s.log.Debugf(
				"\U0001F4E5 <blue>Inbound Stream Data</blue> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Bytes</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Ack</blue>: <cyan>%t</cyan> <magenta>|</magenta> <blue>Ready Chunks</blue>: <cyan>%d</cyan>",
				vpnPacket.SessionID,
				vpnPacket.StreamID,
				vpnPacket.SequenceNum,
				len(assembledPayload),
				decision.Ack,
				len(decision.ReadyPayload),
			)
		}
		if !decision.Ack {
			if s.log != nil {
				s.log.Debugf(
					"âšï¸  <yellow>Inbound Stream Data Deferred (Window Full/Wait)</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan>",
					vpnPacket.SessionID,
					vpnPacket.StreamID,
					vpnPacket.SequenceNum,
				)
			}
			return
		}

		if decision.CloseWrite && s.log != nil {
			s.log.Debugf(
				"\u2705 <green>Inbound Stream FIN Sequenced</green> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan>",
				vpnPacket.SessionID,
				vpnPacket.StreamID,
			)
		}
		if streamRecord.UpstreamConn == nil || !streamRecord.Connected {
			_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
				PacketType:  Enums.PACKET_STREAM_RST,
				StreamID:    vpnPacket.StreamID,
				SequenceNum: 0,
			})
			return
		}
		for _, readyPayload := range decision.ReadyPayload {
			if len(readyPayload) == 0 {
				continue
			}
			if s.log != nil {
				s.log.Debugf(
					"\U0001F4DD <blue>Writing Upstream Data</blue> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Bytes</blue>: <cyan>%d</cyan>",
					vpnPacket.SessionID,
					vpnPacket.StreamID,
					len(readyPayload),
				)
			}
			if _, err := streamRecord.UpstreamConn.Write(readyPayload); err != nil {
				if s.log != nil {
					s.log.Debugf(
						"\U0001F4A5 <yellow>Upstream Write Failed</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <cyan>%v</cyan>",
						vpnPacket.SessionID,
						vpnPacket.StreamID,
						err,
					)
				}
				_ = s.streams.MarkReset(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, now)
				s.streamOutbound.ClearStream(vpnPacket.SessionID, vpnPacket.StreamID)
				s.removeStreamDataFragmentsForStream(vpnPacket.SessionID, vpnPacket.StreamID)
				s.deferredSession.RemoveLane(deferredSessionLaneForPacket(vpnPacket))
				_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
					PacketType:  Enums.PACKET_STREAM_RST,
					StreamID:    vpnPacket.StreamID,
					SequenceNum: 0,
				})
				return
			}
		}

		if decision.CloseWrite {
			_ = s.streams.FinalizeIfDrained(
				vpnPacket.SessionID,
				vpnPacket.StreamID,
				now,
				s.streamOutbound.HasPendingStream(vpnPacket.SessionID, vpnPacket.StreamID),
			)
		}

		_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
			PacketType:  Enums.PACKET_STREAM_DATA_ACK,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: vpnPacket.SequenceNum,
		})
		if s.log != nil {
			s.log.Debugf(
				"\u2705 <green>Queued Stream Data ACK</green> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan>",
				vpnPacket.SessionID,
				vpnPacket.StreamID,
				vpnPacket.SequenceNum,
			)
		}
	default:
		_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
			PacketType:  Enums.PACKET_STREAM_RST,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: 0,
		})
	}
}

func (s *Server) handleDNSQueryRequest(decision domainMatcher.Decision, vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if sessionRecord == nil || vpnPacket.StreamID != 0 || !vpnPacket.HasSequenceNum {
		return false
	}
	totalFragments := vpnPacket.TotalFragments
	if totalFragments == 0 {
		totalFragments = 1
	}
	now := time.Now()
	if s.log != nil {
		s.log.Debugf(
			"\U0001F4E8 <green>Tunnel DNS Query Received</green> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Frag</blue>: <cyan>%d/%d</cyan> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan>",
			vpnPacket.SessionID,
			vpnPacket.SequenceNum,
			vpnPacket.FragmentID+1,
			max(1, int(totalFragments)),
			decision.RequestName,
		)
	}
	_ = s.queueMainSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
		PacketType:     Enums.PACKET_DNS_QUERY_REQ_ACK,
		StreamID:       0,
		SequenceNum:    vpnPacket.SequenceNum,
		FragmentID:     vpnPacket.FragmentID,
		TotalFragments: totalFragments,
	})

	assembledQuery, ready, completed := s.collectDNSQueryFragments(
		vpnPacket.SessionID,
		vpnPacket.SequenceNum,
		vpnPacket.Payload,
		vpnPacket.FragmentID,
		totalFragments,
		now,
	)
	if completed {
		return true
	}
	if !ready {
		if s.log != nil {
			s.log.Debugf(
				"\U0001F9E9 <green>Tunnel DNS Fragment Buffered</green> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Frag</blue>: <cyan>%d/%d</cyan>",
				vpnPacket.SessionID,
				vpnPacket.SequenceNum,
				vpnPacket.FragmentID+1,
				max(1, int(totalFragments)),
			)
		}
		return true
	}

	run := func() {
		s.processDeferredDNSQuery(
			vpnPacket.SessionID,
			vpnPacket.SequenceNum,
			sessionRecord.DownloadCompression,
			sessionRecord.DownloadMTUBytes,
			assembledQuery,
		)
	}
	if !s.dispatchDeferredSessionPacket(vpnPacket, run) {
		run()
	}
	return true
}

func (s *Server) handleDNSQueryResponseAck(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if sessionRecord == nil || vpnPacket.StreamID != 0 || !vpnPacket.HasSequenceNum {
		return false
	}
	totalFragments := vpnPacket.TotalFragments
	if totalFragments == 0 {
		totalFragments = 1
	}
	s.streamOutbound.Ack(
		vpnPacket.SessionID,
		vpnPacket.PacketType,
		0,
		vpnPacket.SequenceNum,
		vpnPacket.FragmentID,
		totalFragments,
	)
	return true
}

func (s *Server) handleStreamSynRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum || sessionRecord == nil {
		return false
	}
	run := func() {
		s.processDeferredStreamSyn(vpnPacket, sessionRecord)
	}
	if !s.dispatchDeferredSessionPacket(vpnPacket, run) {
		run()
	}
	return true
}

func (s *Server) handleSOCKS5SynRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum || sessionRecord == nil {
		return false
	}
	run := func() {
		s.processDeferredSOCKS5Syn(vpnPacket, sessionRecord)
	}
	if !s.dispatchDeferredSessionPacket(vpnPacket, run) {
		run()
	}
	return true
}

func (s *Server) mapSOCKSConnectError(err error) uint8 {
	if err == nil {
		return Enums.PACKET_SOCKS5_CONNECT_FAIL
	}

	var upstreamErr *upstreamSOCKS5Error
	if errors.As(err, &upstreamErr) {
		return upstreamErr.packetType
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return Enums.PACKET_SOCKS5_HOST_UNREACHABLE
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Timeout() {
		return Enums.PACKET_SOCKS5_TTL_EXPIRED
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return Enums.PACKET_SOCKS5_TTL_EXPIRED
	}

	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "connection refused"):
		return Enums.PACKET_SOCKS5_CONNECTION_REFUSED
	case strings.Contains(message, "network is unreachable"):
		return Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE
	case strings.Contains(message, "no route to host"),
		strings.Contains(message, "host is unreachable"),
		strings.Contains(message, "no such host"):
		return Enums.PACKET_SOCKS5_HOST_UNREACHABLE
	case strings.Contains(message, "i/o timeout"),
		strings.Contains(message, "timed out"):
		return Enums.PACKET_SOCKS5_TTL_EXPIRED
	default:
		return Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE
	}
}

func (s *Server) handleStreamDataRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum || sessionRecord == nil {
		return false
	}
	run := func() {
		s.processDeferredStreamData(vpnPacket)
	}
	if !s.dispatchDeferredSessionPacket(vpnPacket, run) {
		run()
	}
	return true
}

func (s *Server) handleStreamFinRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum || sessionRecord == nil {
		return false
	}
	now := time.Now()
	if existing, ok, duplicate := s.streams.IsDuplicateRemoteFin(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, now); ok && existing != nil && duplicate {
		_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
			PacketType:  Enums.PACKET_STREAM_FIN_ACK,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: vpnPacket.SequenceNum,
		})
		return true
	}
	_, decision, ok := s.streams.MarkRemoteFin(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, now)
	if !ok {
		_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
			PacketType:  Enums.PACKET_STREAM_RST,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: 0,
		})
		return true
	}
	_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
		PacketType:  Enums.PACKET_STREAM_FIN_ACK,
		StreamID:    vpnPacket.StreamID,
		SequenceNum: vpnPacket.SequenceNum,
	})
	if decision.CloseWrite {
		_ = s.streams.FinalizeIfDrained(
			vpnPacket.SessionID,
			vpnPacket.StreamID,
			now,
			s.streamOutbound.HasPendingStream(vpnPacket.SessionID, vpnPacket.StreamID),
		)
	}
	return true
}

func (s *Server) handleStreamRSTRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum || sessionRecord == nil {
		return false
	}
	now := time.Now()
	_ = s.streams.MarkReset(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, now)
	s.streamOutbound.ClearStream(vpnPacket.SessionID, vpnPacket.StreamID)
	s.removeStreamDataFragmentsForStream(vpnPacket.SessionID, vpnPacket.StreamID)
	s.deferredSession.RemoveLane(deferredSessionLaneForPacket(vpnPacket))
	_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
		PacketType:  Enums.PACKET_STREAM_RST_ACK,
		StreamID:    vpnPacket.StreamID,
		SequenceNum: vpnPacket.SequenceNum,
	})
	return true
}

func (s *Server) handleStreamAckPacket(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum || sessionRecord == nil {
		return false
	}
	now := time.Now()
	switch vpnPacket.PacketType {
	case Enums.PACKET_STREAM_RST_ACK:
		_ = s.streams.MarkReset(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, now)
		matched := s.streamOutbound.Ack(vpnPacket.SessionID, vpnPacket.PacketType, vpnPacket.StreamID, vpnPacket.SequenceNum, 0, 0)
		if s.log != nil {
			stats := s.streamOutbound.SessionStats(vpnPacket.SessionID)
			s.log.Debugf(
				"\U0001F4EC <blue>Received Stream ACK</blue> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Packet</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Matched</blue>: <cyan>%t</cyan> <magenta>|</magenta> <blue>Pending</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Queued</blue>: <cyan>%d</cyan>",
				vpnPacket.SessionID,
				Enums.PacketTypeName(vpnPacket.PacketType),
				vpnPacket.StreamID,
				vpnPacket.SequenceNum,
				matched,
				stats.Pending,
				stats.SchedulerPending,
			)
		}
		s.streamOutbound.ClearStream(vpnPacket.SessionID, vpnPacket.StreamID)
		s.removeStreamDataFragmentsForStream(vpnPacket.SessionID, vpnPacket.StreamID)
	case Enums.PACKET_STREAM_DATA_ACK, Enums.PACKET_STREAM_FIN_ACK, Enums.PACKET_STREAM_SYN_ACK:
		_, _ = s.streams.Touch(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, now)
		matched := s.streamOutbound.Ack(vpnPacket.SessionID, vpnPacket.PacketType, vpnPacket.StreamID, vpnPacket.SequenceNum, 0, 0)
		if s.log != nil {
			stats := s.streamOutbound.SessionStats(vpnPacket.SessionID)
			s.log.Debugf(
				"\U0001F4EC <blue>Received Stream ACK</blue> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Packet</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Matched</blue>: <cyan>%t</cyan> <magenta>|</magenta> <blue>Pending</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Queued</blue>: <cyan>%d</cyan>",
				vpnPacket.SessionID,
				Enums.PacketTypeName(vpnPacket.PacketType),
				vpnPacket.StreamID,
				vpnPacket.SequenceNum,
				matched,
				stats.Pending,
				stats.SchedulerPending,
			)
		}
		if vpnPacket.PacketType == Enums.PACKET_STREAM_FIN_ACK {
			_, _ = s.streams.MarkLocalFinAck(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, now)
			_ = s.streams.FinalizeIfDrained(
				vpnPacket.SessionID,
				vpnPacket.StreamID,
				now,
				s.streamOutbound.HasPendingStream(vpnPacket.SessionID, vpnPacket.StreamID),
			)
		}
	}
	return true
}

func (s *Server) expireStalledOutboundStreams(sessionID uint8, now time.Time) {
	if s == nil {
		return
	}
	streamOutbound := s.streamOutbound
	expired := streamOutbound.ExpireStalled(sessionID, now, s.streamOutboundMaxRetry, s.streamOutboundTTL)
	if len(expired) == 0 {
		return
	}
	streams := s.streams
	deferred := s.deferredSession
	log := s.log
	for _, streamID := range expired {
		sequenceNum, ok := streams.ResetWithNextOutboundSequence(sessionID, streamID, now)
		if !ok {
			continue
		}
		deferred.RemoveLane(deferredSessionLane{sessionID: sessionID, streamID: streamID})
		_ = s.queueMainSessionPacket(sessionID, VpnProto.Packet{
			PacketType:  Enums.PACKET_STREAM_RST,
			StreamID:    streamID,
			SequenceNum: sequenceNum,
		})
		if log != nil {
			log.Warnf(
				"\U0001F6AB <yellow>Stream ARQ Retry Budget Exhausted, Session: <cyan>%d</cyan>, Stream: <cyan>%d</cyan></yellow>",
				sessionID,
				streamID,
			)
		}
	}
}


