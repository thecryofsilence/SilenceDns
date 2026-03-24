// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"time"

	"masterdnsvpn-go/internal/arq"
	domainMatcher "masterdnsvpn-go/internal/domainmatcher"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func (s *Server) handlePostSessionPacket(decision domainMatcher.Decision, vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if handled := s.handleClosedStreamPacket(vpnPacket); handled {
		return true
	}
	if handled := s.preprocessInboundPacket(vpnPacket); handled {
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
	case Enums.PACKET_SOCKS5_CONNECTED_ACK,
		Enums.PACKET_SOCKS5_CONNECT_FAIL_ACK,
		Enums.PACKET_SOCKS5_RULESET_DENIED_ACK,
		Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK,
		Enums.PACKET_SOCKS5_HOST_UNREACHABLE_ACK,
		Enums.PACKET_SOCKS5_CONNECTION_REFUSED_ACK,
		Enums.PACKET_SOCKS5_TTL_EXPIRED_ACK,
		Enums.PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK,
		Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
		Enums.PACKET_SOCKS5_AUTH_FAILED_ACK,
		Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK:
		return s.handleSocksAckPacket(vpnPacket, sessionRecord)
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

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return false
	}

	now := time.Now()
	if !record.isRecentlyClosed(vpnPacket.StreamID, now) {
		return false
	}

	return s.enqueueMissingStreamReset(record, vpnPacket)
}

func (s *Server) enqueueMissingStreamReset(record *sessionRecord, vpnPacket VpnProto.Packet) bool {
	if s == nil || record == nil || vpnPacket.StreamID == 0 {
		return false
	}

	switch vpnPacket.PacketType {
	case Enums.PACKET_STREAM_RST:
		record.enqueueOrphanReset(Enums.PACKET_STREAM_RST_ACK, vpnPacket.StreamID, vpnPacket.SequenceNum)
	case Enums.PACKET_STREAM_RST_ACK:
		return true
	default:
		record.enqueueOrphanReset(Enums.PACKET_STREAM_RST, vpnPacket.StreamID, 0)
	}
	return true
}

func isStreamCreationPacketType(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_STREAM_SYN, Enums.PACKET_SOCKS5_SYN:
		return true
	default:
		return false
	}
}

func isStreamScopedAckPacket(packetType uint8) bool {
	if packetType == Enums.PACKET_STREAM_DATA_ACK {
		return true
	}
	_, ok := Enums.ReverseControlAckFor(packetType)
	return ok
}

func (s *Server) consumeInboundStreamAck(vpnPacket VpnProto.Packet, stream *Stream_server) {
	if s == nil || stream == nil || stream.ARQ == nil {
		return
	}

	handledAck := stream.ARQ.HandleAckPacket(vpnPacket.PacketType, vpnPacket.SequenceNum, vpnPacket.FragmentID)
	now := time.Now()

	if handledAck && vpnPacket.PacketType == Enums.PACKET_STREAM_RST_ACK {
		s.removeStreamDataFragmentsForStream(vpnPacket.SessionID, vpnPacket.StreamID)
		stream.mu.Lock()
		stream.Status = "CLOSED"
		if stream.CloseTime.IsZero() {
			stream.CloseTime = now
		}
		stream.mu.Unlock()
	} else if handledAck && vpnPacket.PacketType == Enums.PACKET_STREAM_FIN_ACK {
		if stream.ARQ.IsClosed() {
			stream.mu.Lock()
			stream.Status = "CLOSED"
			if stream.CloseTime.IsZero() {
				stream.CloseTime = now
			}
			stream.mu.Unlock()
		}
	}
}

func (s *Server) queueImmediateControlAck(record *sessionRecord, packet VpnProto.Packet) bool {
	if s == nil || record == nil {
		return false
	}

	ackType, ok := Enums.ControlAckFor(packet.PacketType)
	if !ok {
		return false
	}

	ackPacket := VpnProto.Packet{
		PacketType:     ackType,
		StreamID:       packet.StreamID,
		SequenceNum:    packet.SequenceNum,
		FragmentID:     packet.FragmentID,
		TotalFragments: packet.TotalFragments,
	}

	if packet.StreamID == 0 {
		return s.queueSessionPacket(record.ID, ackPacket)
	}

	stream, exists := record.getStream(packet.StreamID)
	if (!exists || stream == nil) && isStreamCreationPacketType(packet.PacketType) {
		stream = record.getOrCreateStream(packet.StreamID, s.streamARQConfig(packet.PacketType == Enums.PACKET_SOCKS5_SYN, record.DownloadCompression), nil, s.log)
		exists = stream != nil
	}
	if !exists || stream == nil {
		return false
	}

	if packet.PacketType == Enums.PACKET_SOCKS5_SYN && stream.ARQ != nil {
		return stream.ARQ.SendControlPacketWithTTL(
			ackType,
			packet.SequenceNum,
			packet.FragmentID,
			packet.TotalFragments,
			nil,
			Enums.DefaultPacketPriority(ackType),
			false,
			nil,
			120*time.Second,
		)
	}

	return stream.PushTXPacket(
		Enums.DefaultPacketPriority(ackType),
		ackType,
		packet.SequenceNum,
		packet.FragmentID,
		packet.TotalFragments,
		0,
		0,
		nil,
	)
}

func (s *Server) preprocessInboundPacket(vpnPacket VpnProto.Packet) bool {
	if s == nil {
		return true
	}

	switch vpnPacket.PacketType {
	case Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_RESEND, Enums.PACKET_PACKED_CONTROL_BLOCKS:
		return false
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return false
	}

	if vpnPacket.HasStreamID && vpnPacket.StreamID != 0 {
		now := time.Now()
		if isStreamCreationPacketType(vpnPacket.PacketType) && record.isRecentlyClosed(vpnPacket.StreamID, now) {
			return s.enqueueMissingStreamReset(record, vpnPacket)
		}
		if !isStreamCreationPacketType(vpnPacket.PacketType) {
			if _, exists := record.getStream(vpnPacket.StreamID); !exists {
				return s.enqueueMissingStreamReset(record, vpnPacket)
			}
		}
		if record.isRecentlyClosed(vpnPacket.StreamID, now) {
			return s.enqueueMissingStreamReset(record, vpnPacket)
		}
	}

	_ = s.queueImmediateControlAck(record, vpnPacket)
	if vpnPacket.HasStreamID && vpnPacket.StreamID != 0 && isStreamScopedAckPacket(vpnPacket.PacketType) {
		stream, exists := record.getStream(vpnPacket.StreamID)
		if !exists || stream == nil {
			return s.enqueueMissingStreamReset(record, vpnPacket)
		}
		s.consumeInboundStreamAck(vpnPacket, stream)
		return true
	}
	return false
}

func (s *Server) handlePingRequest(_ VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	return sessionRecord != nil
}

func (s *Server) handlePackedControlBlocksRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if sessionRecord == nil || len(vpnPacket.Payload) < VpnProto.PackedControlBlockSize {
		return false
	}

	handled := false
	sawBlock := false
	VpnProto.ForEachPackedControlBlock(vpnPacket.Payload, func(packetType uint8, streamID uint16, sequenceNum uint16, fragmentID uint8, totalFragments uint8) bool {
		if packetType == Enums.PACKET_PACKED_CONTROL_BLOCKS {
			return true
		}
		sawBlock = true
		block := VpnProto.Packet{
			SessionID:      vpnPacket.SessionID,
			SessionCookie:  vpnPacket.SessionCookie,
			PacketType:     packetType,
			StreamID:       streamID,
			HasStreamID:    true,
			SequenceNum:    sequenceNum,
			HasSequenceNum: true,
			FragmentID:     fragmentID,
			TotalFragments: totalFragments,
		}
		if s.preprocessInboundPacket(block) {
			handled = true
			return true
		}
		if s.handlePackedPostSessionBlock(block, sessionRecord) {
			handled = true
		}
		return true
	})
	return handled || sawBlock
}

func (s *Server) handlePackedPostSessionBlock(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	switch vpnPacket.PacketType {
	case Enums.PACKET_PING:
		return s.handlePingRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_DNS_QUERY_RES_ACK:
		return s.handleDNSQueryResponseAck(vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_DATA_ACK, Enums.PACKET_STREAM_FIN_ACK, Enums.PACKET_STREAM_RST_ACK, Enums.PACKET_STREAM_SYN_ACK:
		return s.handleStreamAckPacket(vpnPacket, sessionRecord)
	case Enums.PACKET_SOCKS5_CONNECTED_ACK,
		Enums.PACKET_SOCKS5_CONNECT_FAIL_ACK,
		Enums.PACKET_SOCKS5_RULESET_DENIED_ACK,
		Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK,
		Enums.PACKET_SOCKS5_HOST_UNREACHABLE_ACK,
		Enums.PACKET_SOCKS5_CONNECTION_REFUSED_ACK,
		Enums.PACKET_SOCKS5_TTL_EXPIRED_ACK,
		Enums.PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK,
		Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
		Enums.PACKET_SOCKS5_AUTH_FAILED_ACK,
		Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK:
		return s.handleSocksAckPacket(vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_FIN:
		return s.handleStreamFinRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_RST:
		return s.handleStreamRSTRequest(vpnPacket, sessionRecord)
	default:
		return false
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
	if s.log != nil && totalFragments == 1 {
		s.log.Debugf(
			"\U0001F4E8 <green>Tunnel DNS Query Received</green> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Frag</blue>: <cyan>%d/%d</cyan> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan>",
			vpnPacket.SessionID,
			vpnPacket.SequenceNum,
			vpnPacket.FragmentID+1,
			max(1, int(totalFragments)),
			decision.RequestName,
		)
	}
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
		if s.log != nil && totalFragments == 1 {
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
	if sessionRecord == nil {
		return false
	}

	totalFragments := vpnPacket.TotalFragments
	if totalFragments == 0 {
		totalFragments = 1
	}
	return s.handleStreamAckPacket(vpnPacket, sessionRecord)
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
	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return false
	}
	if record.isRecentlyClosed(vpnPacket.StreamID, time.Now()) {
		record.enqueueOrphanReset(Enums.PACKET_STREAM_RST, vpnPacket.StreamID, 0)
		return true
	}
	run := func() {
		s.processDeferredSOCKS5Syn(vpnPacket, sessionRecord)
	}
	if !s.dispatchDeferredSessionPacket(vpnPacket, run) {
		run()
	}
	return true
}

func (s *Server) handleStreamDataRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum || sessionRecord == nil {
		return false
	}
	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return false
	}
	if _, exists := record.getStream(vpnPacket.StreamID); !exists {
		return s.enqueueMissingStreamReset(record, vpnPacket)
	}
	run := func() {
		s.processDeferredStreamData(vpnPacket, sessionRecord)
	}
	if !s.dispatchDeferredSessionPacket(vpnPacket, run) {
		run()
	}
	return true
}

func (s *Server) handleStreamFinRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum {
		return false
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return false
	}
	stream, exists := record.getStream(vpnPacket.StreamID)
	if !exists || stream == nil {
		return s.enqueueMissingStreamReset(record, vpnPacket)
	}
	stream.ARQ.MarkFinReceived()
	return true
}

func (s *Server) handleStreamRSTRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 {
		return false
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return false
	}

	now := time.Now()
	stream, ok := record.getStream(vpnPacket.StreamID)
	if ok && stream != nil {
		stream.ARQ.MarkRstReceived()
		stream.ARQ.Close("peer reset before/while connect", arq.CloseOptions{Force: true})
		stream.mu.Lock()
		stream.Status = "CLOSED"
		stream.CloseTime = now
		stream.mu.Unlock()
	} else {
		record.noteStreamClosed(vpnPacket.StreamID, now)
	}

	s.removeSOCKS5SynFragmentsForStream(vpnPacket.SessionID, vpnPacket.StreamID)
	s.removeStreamDataFragmentsForStream(vpnPacket.SessionID, vpnPacket.StreamID)
	return true
}

func (s *Server) handleStreamAckPacket(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum {
		return false
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return false
	}
	stream, exists := record.getStream(vpnPacket.StreamID)
	if !exists || stream == nil {
		return s.enqueueMissingStreamReset(record, vpnPacket)
	}

	s.consumeInboundStreamAck(vpnPacket, stream)
	return true
}

func (s *Server) handleSocksAckPacket(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if sessionRecord == nil || !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 {
		return false
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return false
	}

	stream, exists := record.getStream(vpnPacket.StreamID)
	if !exists || stream == nil || stream.ARQ == nil {
		return s.enqueueMissingStreamReset(record, vpnPacket)
	}

	s.consumeInboundStreamAck(vpnPacket, stream)
	return true
}

func (s *Server) expireStalledOutboundStreams(sessionID uint8, now time.Time) {
	// Refactored: STALLED streams are now handled by ARQ's inactivityTimeout and maxRetries internally.
	// This function remains to support legacy cleanup if needed, but primary logic is moved to ARQ.
}
