// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/compression"
	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/dnscache"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	"masterdnsvpn-go/internal/domainmatcher"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	mtuProbeModeRaw    = 0
	mtuProbeModeBase64 = 1
	mtuProbeCodeLength = 4
	mtuProbeMetaLength = mtuProbeCodeLength + 2
	sessionAcceptSize  = 7
)

type Server struct {
	cfg                     config.ServerConfig
	log                     *logger.Logger
	codec                   *security.Codec
	domainMatcher           *domainmatcher.Matcher
	sessions                *sessionStore
	streams                 *streamStateStore
	invalidCookieTracker    *invalidCookieTracker
	dnsCache                *dnscache.Store
	dnsResolveInflight      *dnsResolveInflightManager
	dnsUpstreamServers      []string
	dnsFragmentMu           sync.Mutex
	dnsFragments            map[dnsFragmentKey]*dnsFragmentEntry
	resolveDNSQueryFn       func([]byte) ([]byte, error)
	uploadCompressionMask   uint8
	downloadCompressionMask uint8
	packetPool              sync.Pool
	droppedPackets          atomic.Uint64
	lastDropLogUnix         atomic.Int64
}

type request struct {
	buf  []byte
	size int
	addr *net.UDPAddr
}

func New(cfg config.ServerConfig, log *logger.Logger, codec *security.Codec) *Server {
	return &Server{
		cfg:                  cfg,
		log:                  log,
		codec:                codec,
		domainMatcher:        domainmatcher.New(cfg.Domain, cfg.MinVPNLabelLength),
		sessions:             newSessionStore(),
		streams:              newStreamStateStore(),
		invalidCookieTracker: newInvalidCookieTracker(),
		dnsCache: dnscache.New(
			cfg.DNSCacheMaxRecords,
			time.Duration(cfg.DNSCacheTTLSeconds*float64(time.Second)),
			cfg.DNSFragmentAssemblyTimeout(),
		),
		dnsResolveInflight:      newDNSResolveInflightManager(cfg.DNSFragmentAssemblyTimeout()),
		dnsUpstreamServers:      append([]string(nil), cfg.DNSUpstreamServers...),
		dnsFragments:            make(map[dnsFragmentKey]*dnsFragmentEntry, 32),
		uploadCompressionMask:   buildCompressionMask(cfg.SupportedUploadCompressionTypes),
		downloadCompressionMask: buildCompressionMask(cfg.SupportedDownloadCompressionTypes),
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
		s.log.Warnf("⚠️ <yellow>UDP Read Buffer Setup Failed</yellow> <magenta>|</magenta> <cyan>%v</cyan>", err)
	}
	if err := conn.SetWriteBuffer(s.cfg.SocketBufferSize); err != nil {
		s.log.Warnf("⚠️ <yellow>UDP Write Buffer Setup Failed</yellow> <magenta>|</magenta> <cyan>%v</cyan>", err)
	}

	s.log.Infof(
		"🛰️ <green>UDP Listener Ready</green> <magenta>|</magenta> <blue>Addr</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Readers</blue>: <magenta>%d</magenta> <magenta>|</magenta> <blue>Workers</blue>: <magenta>%d</magenta> <magenta>|</magenta> <blue>Queue</blue>: <magenta>%d</magenta>",
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

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			expired := s.sessions.Cleanup(now, s.cfg.SessionTimeout(), s.cfg.ClosedSessionRetention())
			s.invalidCookieTracker.Cleanup(now, s.cfg.InvalidCookieWindow())
			s.purgeDNSQueryFragments(now)
			if len(expired) == 0 {
				continue
			}
			for _, sessionID := range expired {
				s.streams.RemoveSession(sessionID)
			}
			s.log.Infof(
				"🧹 <green>Expired Sessions Cleaned</green> <magenta>|</magenta> <blue>Count</blue>: <cyan>%d</cyan>",
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
				"📥 <yellow>UDP Read Error</yellow> <magenta>|</magenta> <blue>Reader</blue>: <cyan>%d</cyan> <magenta>|</magenta> <cyan>%v</cyan>",
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

			payload := req.buf[:req.size]
			response := s.safeHandlePacket(payload)
			if len(response) == 0 {
				s.packetPool.Put(req.buf)
				continue
			}

			if _, err := conn.WriteToUDP(response, req.addr); err != nil {
				s.log.Debugf(
					"📤 <yellow>UDP Write Error</yellow> <magenta>|</magenta> <blue>Worker</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Remote</blue>: <cyan>%s</cyan> <magenta>|</magenta> <cyan>%v</cyan>",
					workerID,
					req.addr.String(),
					err,
				)
				s.packetPool.Put(req.buf)
				continue
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
					"💥 <red>Packet Handler Panic Recovered</red> <magenta>|</magenta> <yellow>%v</yellow>",
					recovered,
				)
			}
			response = nil
		}
	}()
	return s.handlePacket(packet)
}

func (s *Server) handlePacket(packet []byte) []byte {
	if !DnsParser.LooksLikeDNSRequest(packet) {
		return nil
	}

	parsed, err := DnsParser.ParsePacketLite(packet)
	if err != nil {
		return buildFormatErrorResponse(packet)
	}

	if !parsed.HasQuestion {
		return buildFormatErrorResponse(packet)
	}

	decision := s.domainMatcher.Match(parsed)
	switch decision.Action {
	case domainmatcher.ActionProcess:
		return s.handleTunnelCandidate(packet, parsed, decision)
	case domainmatcher.ActionFormatError:
		return buildFormatErrorResponseLite(packet, parsed)
	case domainmatcher.ActionNoData:
		return buildNoDataResponseLite(packet, parsed)
	default:
		return nil
	}
}

func (s *Server) handleTunnelCandidate(packet []byte, parsed DnsParser.LitePacket, decision domainmatcher.Decision) []byte {
	vpnPacket, err := VpnProto.ParseFromLabels(decision.Labels, s.codec)
	if err != nil {
		return buildNoDataResponseLite(packet, parsed)
	}
	vpnPacket, err = VpnProto.InflatePayload(vpnPacket)
	if err != nil {
		return buildNoDataResponseLite(packet, parsed)
	}
	if !isPreSessionRequestType(vpnPacket.PacketType) {
		now := time.Now()
		validation := s.sessions.ValidateAndTouch(vpnPacket.SessionID, vpnPacket.SessionCookie, now)
		lookup := validation.Lookup
		hasExpectedCookie := validation.Known
		if !validation.Valid {
			var expectedCookiePtr *uint8
			if hasExpectedCookie {
				expectedCookiePtr = &lookup.Cookie
			}
			shouldEmit := s.invalidCookieTracker.Note(
				vpnPacket.SessionID,
				expectedCookiePtr,
				vpnPacket.SessionCookie,
				lookup.State,
				now,
				s.cfg.InvalidCookieWindow(),
				s.cfg.InvalidCookieErrorThreshold,
			)
			if shouldEmit {
				if hasExpectedCookie && lookup.State == sessionLookupClosed {
					s.log.Warnf(
						"🧷 <yellow>Stale Closed Session Cookie Threshold Reached</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Expected</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Received</blue>: <cyan>%d</cyan>",
						vpnPacket.SessionID,
						lookup.Cookie,
						vpnPacket.SessionCookie,
					)
				} else if hasExpectedCookie {
					s.log.Warnf(
						"🧷 <yellow>Invalid Session Cookie Threshold Reached</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Expected</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Received</blue>: <cyan>%d</cyan>",
						vpnPacket.SessionID,
						lookup.Cookie,
						vpnPacket.SessionCookie,
					)
				} else {
					s.log.Warnf(
						"🧷 <yellow>Unknown Session Cookie Threshold Reached</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Received</blue>: <cyan>%d</cyan>",
						vpnPacket.SessionID,
						vpnPacket.SessionCookie,
					)
				}
				if hasExpectedCookie {
					if response := s.buildInvalidSessionErrorResponse(packet, decision.RequestName, vpnPacket.SessionID, lookup.ResponseMode); len(response) != 0 {
						return response
					}
				}
			}
			return nil
		}
	}

	switch vpnPacket.PacketType {
	case Enums.PACKET_SESSION_INIT:
		return s.handleSessionInitRequest(packet, decision, vpnPacket)
	case Enums.PACKET_MTU_UP_REQ:
		return s.handleMTUUpRequest(packet, parsed, decision, vpnPacket)
	case Enums.PACKET_MTU_DOWN_REQ:
		return s.handleMTUDownRequest(packet, parsed, decision, vpnPacket)
	case Enums.PACKET_PING:
		return s.handlePingRequest(packet, decision, vpnPacket)
	case Enums.PACKET_DNS_QUERY_REQ:
		return s.handleDNSQueryRequest(packet, parsed, decision, vpnPacket)
	case Enums.PACKET_STREAM_SYN:
		return s.handleStreamSynRequest(packet, decision, vpnPacket)
	case Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_RESEND:
		return s.handleStreamDataRequest(packet, decision, vpnPacket)
	case Enums.PACKET_STREAM_FIN:
		return s.handleStreamFinRequest(packet, decision, vpnPacket)
	case Enums.PACKET_STREAM_RST:
		return s.handleStreamRSTRequest(packet, decision, vpnPacket)
	case Enums.PACKET_STREAM_DATA_ACK, Enums.PACKET_STREAM_FIN_ACK, Enums.PACKET_STREAM_RST_ACK, Enums.PACKET_STREAM_SYN_ACK:
		return s.handleStreamAckPacket(packet, decision, vpnPacket)
	default:
		return buildNoDataResponseLite(packet, parsed)
	}
}

func buildFormatErrorResponse(packet []byte) []byte {
	response, err := DnsParser.BuildFormatErrorResponse(packet)
	if err != nil {
		return nil
	}
	return response
}

func buildFormatErrorResponseLite(packet []byte, parsed DnsParser.LitePacket) []byte {
	response, err := DnsParser.BuildFormatErrorResponseFromLite(packet, parsed)
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
	payload := make([]byte, 8)
	copy(payload, []byte{'I', 'N', 'V'})
	if _, err := rand.Read(payload[3:]); err != nil {
		return nil
	}

	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, requestName, VpnProto.Packet{
		SessionID:  sessionID,
		PacketType: Enums.PACKET_ERROR_DROP,
		Payload:    payload,
	}, responseMode == mtuProbeModeBase64)
	if err != nil {
		return nil
	}
	return response
}

func (s *Server) buildSessionVPNResponse(questionPacket []byte, requestName string, record *sessionRecord, packet VpnProto.Packet) []byte {
	if record == nil {
		return nil
	}
	packet.SessionID = record.ID
	packet.SessionCookie = record.Cookie
	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, requestName, packet, record.ResponseMode == mtuProbeModeBase64)
	if err != nil {
		return nil
	}
	return response
}

func isPreSessionRequestType(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_SESSION_INIT, Enums.PACKET_MTU_UP_REQ, Enums.PACKET_MTU_DOWN_REQ:
		return true
	default:
		return false
	}
}

func (s *Server) handleSessionInitRequest(questionPacket []byte, decision domainmatcher.Decision, vpnPacket VpnProto.Packet) []byte {
	if vpnPacket.SessionID != 0 || len(vpnPacket.Payload) != sessionInitDataSize {
		return nil
	}
	requestedUpload, requestedDownload := compression.SplitPair(vpnPacket.Payload[1])
	resolvedUpload := resolveCompressionType(requestedUpload, s.uploadCompressionMask)
	resolvedDownload := resolveCompressionType(requestedDownload, s.downloadCompressionMask)

	record, _, err := s.sessions.findOrCreate(
		vpnPacket.Payload,
		resolvedUpload,
		resolvedDownload,
		s.cfg.MaxPacketsPerBatch,
	)
	if err != nil || record == nil {
		return nil
	}

	responsePayload := make([]byte, sessionAcceptSize)
	responsePayload[0] = record.ID
	responsePayload[1] = record.Cookie
	responsePayload[2] = compression.PackPair(record.UploadCompression, record.DownloadCompression)
	copy(responsePayload[3:], record.VerifyCode[:])

	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, decision.RequestName, VpnProto.Packet{
		SessionID:  0,
		PacketType: Enums.PACKET_SESSION_ACCEPT,
		Payload:    responsePayload,
	}, record.ResponseMode == mtuProbeModeBase64)
	if err != nil {
		return nil
	}
	return response
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
	requested = compression.NormalizeType(requested)
	if allowedMask&(1<<requested) != 0 {
		return requested
	}
	return compression.TypeOff
}

func (s *Server) onDrop(addr *net.UDPAddr) {
	total := s.droppedPackets.Add(1)

	now := logger.NowUnixNano()
	last := s.lastDropLogUnix.Load()
	interval := s.cfg.DropLogInterval().Nanoseconds()
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
		"🚧 <yellow>Request Queue Overloaded</yellow> <magenta>|</magenta> <blue>Dropped</blue>: <magenta>%d</magenta> <magenta>|</magenta> <blue>Remote</blue>: <cyan>%s</cyan>",
		total,
		addr.String(),
	)
}

func (s *Server) handleMTUUpRequest(questionPacket []byte, _ DnsParser.LitePacket, decision domainmatcher.Decision, vpnPacket VpnProto.Packet) []byte {
	if len(vpnPacket.Payload) < 1+mtuProbeCodeLength {
		return nil
	}

	baseEncode := vpnPacket.Payload[0] == mtuProbeModeBase64
	if vpnPacket.Payload[0] != mtuProbeModeRaw && vpnPacket.Payload[0] != mtuProbeModeBase64 {
		return nil
	}
	probeCode := vpnPacket.Payload[1 : 1+mtuProbeCodeLength]
	responsePayload := make([]byte, mtuProbeMetaLength)
	copy(responsePayload, probeCode)
	binary.BigEndian.PutUint16(responsePayload[mtuProbeCodeLength:], uint16(len(vpnPacket.Payload)))
	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, decision.RequestName, VpnProto.Packet{
		SessionID:  vpnPacket.SessionID,
		PacketType: Enums.PACKET_MTU_UP_RES,
		Payload:    responsePayload,
	}, baseEncode)
	if err != nil {
		return nil
	}
	return response
}

func (s *Server) handleMTUDownRequest(questionPacket []byte, _ DnsParser.LitePacket, decision domainmatcher.Decision, vpnPacket VpnProto.Packet) []byte {
	if len(vpnPacket.Payload) < 1+mtuProbeCodeLength+2 {
		return nil
	}

	baseEncode := vpnPacket.Payload[0] == mtuProbeModeBase64
	if vpnPacket.Payload[0] != mtuProbeModeRaw && vpnPacket.Payload[0] != mtuProbeModeBase64 {
		return nil
	}
	downloadSize := int(binary.BigEndian.Uint16(vpnPacket.Payload[1+mtuProbeCodeLength : 1+mtuProbeCodeLength+2]))
	if downloadSize < 30 || downloadSize > 4096 {
		return nil
	}

	probeCode := vpnPacket.Payload[1 : 1+mtuProbeCodeLength]
	payload := make([]byte, downloadSize)
	copy(payload, probeCode)
	binary.BigEndian.PutUint16(payload[mtuProbeCodeLength:], uint16(downloadSize))
	if downloadSize > mtuProbeMetaLength {
		if _, err := rand.Read(payload[mtuProbeMetaLength:]); err != nil {
			return nil
		}
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

func (s *Server) handlePingRequest(questionPacket []byte, decision domainmatcher.Decision, vpnPacket VpnProto.Packet) []byte {
	sessionRecord, ok := s.sessions.Active(vpnPacket.SessionID)
	if !ok {
		return nil
	}

	payload := []byte{'P', 'O', ':'}
	randomPart := make([]byte, 4)
	if _, err := rand.Read(randomPart); err != nil {
		return nil
	}
	payload = append(payload, randomPart...)

	return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
		PacketType: Enums.PACKET_PONG,
		Payload:    payload,
	})
}

func (s *Server) handleDNSQueryRequest(questionPacket []byte, parsed DnsParser.LitePacket, decision domainmatcher.Decision, vpnPacket VpnProto.Packet) []byte {
	sessionRecord, ok := s.sessions.Active(vpnPacket.SessionID)
	if !ok {
		return nil
	}

	if vpnPacket.StreamID != 0 || !vpnPacket.HasSequenceNum {
		return nil
	}

	if s.log != nil {
		s.log.Debugf(
			"📨 <green>Tunnel DNS Query Received</green> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Frag</blue>: <cyan>%d/%d</cyan> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan>",
			vpnPacket.SessionID,
			vpnPacket.SequenceNum,
			vpnPacket.FragmentID+1,
			max(1, int(vpnPacket.TotalFragments)),
			decision.RequestName,
		)
	}

	assembledQuery, ready := s.collectDNSQueryFragments(
		vpnPacket.SessionID,
		vpnPacket.SequenceNum,
		vpnPacket.Payload,
		vpnPacket.FragmentID,
		vpnPacket.TotalFragments,
		time.Now(),
	)
	if !ready {
		if s.log != nil {
			s.log.Debugf(
				"🧩 <green>Tunnel DNS Fragment Buffered</green> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Frag</blue>: <cyan>%d/%d</cyan>",
				vpnPacket.SessionID,
				vpnPacket.SequenceNum,
				vpnPacket.FragmentID+1,
				max(1, int(vpnPacket.TotalFragments)),
			)
		}
		return buildNoDataResponseLite(questionPacket, parsed)
	}

	rawResponse := s.buildDNSQueryResponsePayload(assembledQuery, vpnPacket.SessionID, vpnPacket.SequenceNum)
	if len(rawResponse) == 0 {
		return nil
	}

	return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
		PacketType:      Enums.PACKET_DNS_QUERY_RES,
		StreamID:        0,
		SequenceNum:     vpnPacket.SequenceNum,
		FragmentID:      0,
		TotalFragments:  1,
		CompressionType: sessionRecord.DownloadCompression,
		Payload:         rawResponse,
	})
}

func (s *Server) handleStreamSynRequest(questionPacket []byte, decision domainmatcher.Decision, vpnPacket VpnProto.Packet) []byte {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum {
		return nil
	}
	sessionRecord, ok := s.sessions.Active(vpnPacket.SessionID)
	if !ok {
		return nil
	}
	s.streams.EnsureOpen(vpnPacket.SessionID, vpnPacket.StreamID, time.Now())
	return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
		PacketType:     Enums.PACKET_STREAM_SYN_ACK,
		StreamID:       vpnPacket.StreamID,
		SequenceNum:    vpnPacket.SequenceNum,
		FragmentID:     0,
		TotalFragments: 0,
	})
}

func (s *Server) handleStreamDataRequest(questionPacket []byte, decision domainmatcher.Decision, vpnPacket VpnProto.Packet) []byte {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum {
		return nil
	}
	sessionRecord, ok := s.sessions.Active(vpnPacket.SessionID)
	if !ok {
		return nil
	}
	streamRecord, ok := s.streams.Touch(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, time.Now())
	if !ok || streamRecord == nil {
		return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
			PacketType:  Enums.PACKET_STREAM_RST,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: 0,
		})
	}
	switch streamRecord.State {
	case Enums.STREAM_STATE_OPEN, Enums.STREAM_STATE_HALF_CLOSED_REMOTE, Enums.STREAM_STATE_DRAINING, Enums.STREAM_STATE_CLOSING, Enums.STREAM_STATE_TIME_WAIT:
		return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
			PacketType:  Enums.PACKET_STREAM_DATA_ACK,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: vpnPacket.SequenceNum,
		})
	default:
		return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
			PacketType:  Enums.PACKET_STREAM_RST,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: 0,
		})
	}
}

func (s *Server) handleStreamFinRequest(questionPacket []byte, decision domainmatcher.Decision, vpnPacket VpnProto.Packet) []byte {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum {
		return nil
	}
	sessionRecord, ok := s.sessions.Active(vpnPacket.SessionID)
	if !ok {
		return nil
	}
	if _, ok := s.streams.MarkRemoteFin(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, time.Now()); !ok {
		return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
			PacketType:  Enums.PACKET_STREAM_RST,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: 0,
		})
	}
	return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
		PacketType:  Enums.PACKET_STREAM_FIN_ACK,
		StreamID:    vpnPacket.StreamID,
		SequenceNum: vpnPacket.SequenceNum,
	})
}

func (s *Server) handleStreamRSTRequest(questionPacket []byte, decision domainmatcher.Decision, vpnPacket VpnProto.Packet) []byte {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum {
		return nil
	}
	sessionRecord, ok := s.sessions.Active(vpnPacket.SessionID)
	if !ok {
		return nil
	}
	_ = s.streams.MarkReset(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, time.Now())
	return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
		PacketType:  Enums.PACKET_STREAM_RST_ACK,
		StreamID:    vpnPacket.StreamID,
		SequenceNum: vpnPacket.SequenceNum,
	})
}

func (s *Server) handleStreamAckPacket(questionPacket []byte, decision domainmatcher.Decision, vpnPacket VpnProto.Packet) []byte {
	_ = questionPacket
	_ = decision
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum {
		return nil
	}
	switch vpnPacket.PacketType {
	case Enums.PACKET_STREAM_RST_ACK:
		_ = s.streams.MarkReset(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, time.Now())
	case Enums.PACKET_STREAM_DATA_ACK, Enums.PACKET_STREAM_FIN_ACK, Enums.PACKET_STREAM_SYN_ACK:
		_, _ = s.streams.Touch(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, time.Now())
	}
	return nil
}
