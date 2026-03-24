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
	"fmt"
	"net"
	"sort"
	"strconv"
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
	return &Server{
		cfg:                  cfg,
		log:                  log,
		codec:                codec,
		domainMatcher:        domainMatcher.New(cfg.Domain, cfg.MinVPNLabelLength),
		sessions:             newSessionStore(),
		deferredSession:      newDeferredSessionProcessor(cfg.DeferredSessionWorkers, cfg.DeferredSessionQueueLimit, log),
		invalidCookieTracker: newInvalidCookieTracker(),
		dnsCache: dnsCache.New(
			cfg.DNSCacheMaxRecords,
			time.Duration(cfg.DNSCacheTTLSeconds*float64(time.Second)),
			dnsFragmentTimeout,
		),
		dnsResolveInflight:  newDNSResolveInflightManager(dnsFragmentTimeout),
		dnsUpstreamServers:  append([]string(nil), cfg.DNSUpstreamServers...),
		dnsFragments:        fragmentstore.New[dnsFragmentKey](32),
		socks5Fragments:     fragmentstore.New[socks5FragmentKey](32),
		streamDataFragments: fragmentstore.New[streamDataFragmentKey](128),
		dnsFragmentTimeout:  dnsFragmentTimeout,
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
		s.log.Warnf("\U0001F4E1 <yellow>UDP Read Buffer Setup Failed, <cyan>%v</cyan></yellow>", err)
	}

	if err := conn.SetWriteBuffer(s.cfg.SocketBufferSize); err != nil {
		s.log.Warnf("\U0001F4E1 <yellow>UDP Write Buffer Setup Failed, <cyan>%v</cyan></yellow>", err)
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
			s.sessions.SweepTerminalStreams(now, 45*time.Second)
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
		if s.debugLoggingEnabled() {
			s.log.Debugf("\u26a0\ufe0f <yellow>DNS Parse Failed</yellow> <magenta>|</magenta> <blue>Error</blue>: <cyan>%v</cyan>", err)
		}
		if errors.Is(err, DnsParser.ErrNotDNSRequest) || errors.Is(err, DnsParser.ErrPacketTooShort) {
			return nil
		}

		return s.buildNoDataResponseLogged(packet, "request-parse-failed")
	}

	if !parsed.HasQuestion {
		return s.buildNoDataResponseLogged(packet, "request-has-no-question")
	}

	decision := s.domainMatcher.Match(parsed)
	if decision.Action == domainMatcher.ActionProcess {
		return s.handleTunnelCandidate(packet, parsed, decision)
	}

	if decision.Action == domainMatcher.ActionFormatError || decision.Action == domainMatcher.ActionNoData {
		return s.buildNoDataResponseLiteLogged(packet, parsed, "domain-match-no-data")
	}

	return nil
}

func (s *Server) handleTunnelCandidate(packet []byte, parsed DnsParser.LitePacket, decision domainMatcher.Decision) []byte {
	vpnPacket, err := VpnProto.ParseInflatedFromLabels(decision.Labels, s.codec)
	if err != nil {
		if s.debugLoggingEnabled() {
			s.log.Debugf("\u26a0\ufe0f <yellow>VPN Proto Parse Failed</yellow> <magenta>|</magenta> <blue>Error</blue>: <cyan>%v</cyan>", err)
		}
		return s.buildNoDataResponseLiteLogged(packet, parsed, "vpn-proto-parse-failed")
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
			return s.buildNoDataResponseLiteLogged(packet, parsed, fmt.Sprintf("post-session-unhandled-%s", Enums.PacketTypeName(vpnPacket.PacketType)))
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
		return s.buildNoDataResponseLiteLogged(packet, parsed, fmt.Sprintf("pre-session-unhandled-%s", Enums.PacketTypeName(vpnPacket.PacketType)))
	}
}

func (s *Server) validatePostSessionPacket(questionPacket []byte, requestName string, vpnPacket VpnProto.Packet) postSessionValidation {
	now := time.Now()
	validation := s.sessions.ValidateAndTouch(vpnPacket.SessionID, vpnPacket.SessionCookie, now)
	if validation.Valid {
		// ARQ handles its own config
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
	s.sessions.mu.Lock()
	record := s.sessions.byID[sessionID]
	s.sessions.mu.Unlock()
	if record == nil {
		return false
	}

	// Push to corresponding stream's TXQueue. Stream 0 is initialized in findOrCreate.
	stream := record.getOrCreateStream(packet.StreamID, s.streamARQConfig(false, record.DownloadCompression), nil, s.log)
	return stream.PushTXPacket(getEffectivePriority(packet.PacketType, 3), packet.PacketType, packet.SequenceNum, packet.FragmentID, packet.TotalFragments, packet.CompressionType, 0, packet.Payload)
}

func (s *Server) streamARQConfig(isSocks bool, compressionType uint8) arq.Config {
	return arq.Config{
		WindowSize:               s.cfg.ARQWindowSize,
		RTO:                      s.cfg.ARQInitialRTOSeconds,
		MaxRTO:                   s.cfg.ARQMaxRTOSeconds,
		StartPaused:              isSocks,
		EnableControlReliability: true,
		ControlRTO:               s.cfg.ARQControlInitialRTOSeconds,
		ControlMaxRTO:            s.cfg.ARQControlMaxRTOSeconds,
		ControlMaxRetries:        s.cfg.ARQMaxControlRetries,
		InactivityTimeout:        s.cfg.ARQInactivityTimeoutSeconds,
		DataPacketTTL:            s.cfg.ARQDataPacketTTLSeconds,
		MaxDataRetries:           s.cfg.ARQMaxDataRetries,
		ControlPacketTTL:         s.cfg.ARQControlPacketTTLSeconds,
		TerminalDrainTimeout:     s.cfg.ARQTerminalDrainTimeoutSec,
		TerminalAckWaitTimeout:   s.cfg.ARQTerminalAckWaitTimeoutSec,
		CompressionType:          compressionType,
	}
}

func (s *Server) queueMainSessionPacket(sessionID uint8, packet VpnProto.Packet) bool {
	packet.StreamID = 0
	return s.queueSessionPacket(sessionID, packet)
}

func (s *Server) cleanupClosedSession(sessionID uint8) {
	if s == nil || sessionID == 0 {
		return
	}
	// s.streams.RemoveSession(sessionID) (removed)
	// s.streamOutbound.RemoveSession(sessionID)
	s.deferredSession.RemoveSession(sessionID)
	s.removeDNSQueryFragmentsForSession(sessionID)
	s.removeStreamDataFragmentsForSession(sessionID)
}

func (s *Server) serveQueuedOrPong(questionPacket []byte, requestName string, record *sessionRuntimeView, now time.Time) []byte {
	if record == nil {
		return nil
	}
	sessionID := record.ID

	// New MLQ-based Round-Robin dispatcher
	if pkt, ok := s.dequeueSessionResponse(sessionID, now); ok {
		// if s.log != nil && s.debugLoggingEnabled() && shouldLogServerPacketFlow(pkt.PacketType) {
		// 	s.log.Debugf(
		// 		"\U0001F4E4 <blue>Serving Queued Packet</blue> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Type</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan>",
		// 		sessionID,
		// 		Enums.PacketTypeName(pkt.PacketType),
		// 		pkt.StreamID,
		// 		pkt.SequenceNum,
		// 	)
		// }
		resp := s.buildSessionVPNResponse(questionPacket, requestName, record, *pkt)
		// No pooling here since rebuildSessionVPNResponse might use it or it's a temp packet
		return resp
	}

	payload := s.nextPongPayload()

	return s.buildSessionVPNResponse(questionPacket, requestName, record, VpnProto.Packet{
		PacketType: Enums.PACKET_PONG,
		Payload:    payload[:],
	})
}

func (s *Server) dequeueSessionResponse(sessionID uint8, now time.Time) (*VpnProto.Packet, bool) {
	s.sessions.mu.Lock()
	record := s.sessions.byID[sessionID]
	s.sessions.mu.Unlock()

	if record == nil {
		return nil, false
	}

	record.mu.Lock()
	defer record.mu.Unlock()

	record.StreamsMu.RLock()
	streamCount := len(record.ActiveStreams)
	ids := make([]int32, 0, streamCount+1)
	for _, id := range record.ActiveStreams {
		ids = append(ids, int32(id))
	}
	record.StreamsMu.RUnlock()

	if record.OrphanQueue != nil && record.OrphanQueue.Size() > 0 {
		ids = append(ids, -1)
	}

	if len(ids) == 0 {
		return nil, false
	}

	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	startIdx := 0
	for i, id := range ids {
		if id >= record.RRStreamID {
			startIdx = i
			break
		}
	}

	for i := 0; i < len(ids); i++ {
		idx := (startIdx + i) % len(ids)
		id := ids[idx]

		var item *serverStreamTXPacket
		var ok bool
		var selectedStreamID uint16

		if id == -1 {
			p, _, popOk := record.OrphanQueue.Pop(func(p VpnProto.Packet) uint64 {
				return Enums.PacketTypeStreamKey(p.StreamID, p.PacketType)
			})
			if popOk {
				item = &serverStreamTXPacket{
					PacketType:     p.PacketType,
					SequenceNum:    p.SequenceNum,
					FragmentID:     p.FragmentID,
					TotalFragments: p.TotalFragments,
					Payload:        p.Payload,
				}
				selectedStreamID = p.StreamID
				ok = true
			}
		} else {
			record.StreamsMu.RLock()
			stream := record.Streams[uint16(id)]
			record.StreamsMu.RUnlock()
			if stream == nil || stream.TXQueue == nil {
				continue
			}
			var popped *serverStreamTXPacket
			popped, _, ok = stream.TXQueue.Pop(func(p *serverStreamTXPacket) uint64 {
				return Enums.PacketIdentityKey(uint16(id), p.PacketType, p.SequenceNum, p.FragmentID)
			})
			if ok {
				item = popped
				selectedStreamID = uint16(id)
			}
		}

		if ok && item != nil {
			record.RRStreamID = id + 1 // Move to next for next call
			if VpnProto.IsPackableControlPacket(item.PacketType, len(item.Payload)) && record.MaxPackedBlocks > 1 {
				return s.packControlBlocks(record, item, id, selectedStreamID), true
			}
			pkt := vpnPacketFromTX(item, selectedStreamID)
			return &pkt, true
		}
	}

	return nil, false
}

func (s *Server) packControlBlocks(record *sessionRecord, first *serverStreamTXPacket, initialID int32, initialStreamID uint16) *VpnProto.Packet {
	limit := record.MaxPackedBlocks
	if limit <= 1 {
		pkt := vpnPacketFromTX(first, initialStreamID)
		return &pkt
	}

	payload := make([]byte, 0, limit*VpnProto.PackedControlBlockSize)
	payload = VpnProto.AppendPackedControlBlock(payload, first.PacketType, initialStreamID, first.SequenceNum, first.FragmentID, first.TotalFragments)
	blocks := 1

	// Get all candidate IDs (Orphans + Active Streams)
	record.StreamsMu.RLock()
	ids := make([]int32, 0, len(record.ActiveStreams)+1)
	if record.OrphanQueue != nil && record.OrphanQueue.Size() > 0 {
		ids = append(ids, -1)
	}
	for _, sid := range record.ActiveStreams {
		ids = append(ids, int32(sid))
	}
	record.StreamsMu.RUnlock()

	// Reorder IDs to prioritize initial stream/source
	orderedIDs := make([]int32, 0, len(ids))
	orderedIDs = append(orderedIDs, initialID)
	for _, id := range ids {
		if id != initialID {
			orderedIDs = append(orderedIDs, id)
		}
	}

	for _, id := range orderedIDs {
		if blocks >= limit {
			break
		}

		if id == -1 {
			for blocks < limit {
				popped, ok := record.OrphanQueue.PopAnyIf(func(p VpnProto.Packet) bool {
					return VpnProto.IsPackableControlPacket(p.PacketType, 0)
				}, func(p VpnProto.Packet) uint64 {
					return Enums.PacketTypeStreamKey(p.StreamID, p.PacketType)
				})
				if !ok {
					break
				}
				payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, popped.StreamID, popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
				blocks++
			}
		} else {
			record.StreamsMu.RLock()
			stream := record.Streams[uint16(id)]
			record.StreamsMu.RUnlock()
			if stream == nil || stream.TXQueue == nil {
				continue
			}
			for blocks < limit {
				popped, ok := stream.TXQueue.PopAnyIf(func(p *serverStreamTXPacket) bool {
					return VpnProto.IsPackableControlPacket(p.PacketType, len(p.Payload))
				}, func(p *serverStreamTXPacket) uint64 {
					return Enums.PacketIdentityKey(uint16(id), p.PacketType, p.SequenceNum, p.FragmentID)
				})
				if !ok {
					break
				}
				payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, uint16(id), popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
				blocks++
			}
		}
	}

	if blocks <= 1 {
		pkt := vpnPacketFromTX(first, initialStreamID)
		return &pkt
	}

	return &VpnProto.Packet{
		PacketType:  Enums.PACKET_PACKED_CONTROL_BLOCKS,
		Payload:     payload,
		StreamID:    0,
		HasStreamID: true,
	}
}

func vpnPacketFromTX(p *serverStreamTXPacket, streamID uint16) VpnProto.Packet {
	return VpnProto.Packet{
		PacketType:         p.PacketType,
		StreamID:           streamID,
		SequenceNum:        p.SequenceNum,
		FragmentID:         p.FragmentID,
		TotalFragments:     p.TotalFragments,
		CompressionType:    p.CompressionType,
		HasCompressionType: p.CompressionType != compression.TypeOff,
		Payload:            p.Payload,
		HasSequenceNum:     p.SequenceNum != 0,
		HasFragmentInfo:    p.FragmentID != 0 || p.TotalFragments != 0,
		HasStreamID:        true,
	}
}

func (s *Server) QueueTargetForPacket(streamExists bool, packetType uint8, streamID uint16) (QueueTarget, bool) {
	if streamID == 0 {
		return QueueTargetMain, true
	}
	if streamExists {
		return QueueTargetStream, true
	}
	// Fallback to Main if stream recently closed
	return QueueTargetMain, true
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
