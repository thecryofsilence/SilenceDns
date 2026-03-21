// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"errors"
	"io"
	"net"
	"time"

	"masterdnsvpn-go/internal/arq"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/streamutil"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const maxClientStreamFollowUps = 16
const streamTXInitialRetryDelay = 800 * time.Millisecond
const streamTXMaxRetryDelay = 2 * time.Second
const streamTXMinRetryDelay = 120 * time.Millisecond

var ErrClientStreamClosed = errors.New("client stream closed")
var ErrClientStreamBackpressure = errors.New("client stream send queue full")

func (c *Client) createStream(streamID uint16, conn net.Conn) *clientStream {
	now := time.Now()
	stream := &clientStream{
		ID:             streamID,
		Conn:           conn,
		NextSequence:   2,
		LastActivityAt: now,
		TXQueue:        make([]clientStreamTXPacket, 0, 8),
		TXInFlight:     make([]clientStreamTXPacket, 0, c.effectiveStreamTXWindow()),
		TXWake:         make(chan struct{}, 1),
		StopCh:         make(chan struct{}),
		retryBase:      streamTXInitialRetryDelay,
		arqWindowSize:  c.arqWindowSize,
		log:            c.log,
	}
	if preferred, ok := c.GetBestConnection(); ok && preferred.Key != "" {
		stream.PreferredServerKey = preferred.Key
		stream.LastResolverFailover = now
	}
	c.storeStream(stream)
	if c.stream0Runtime != nil {
		c.stream0Runtime.NotifyDNSActivity()
	}
	go c.runClientStreamTXLoop(stream, 5*time.Second)
	return stream
}

func (c *Client) nextClientStreamSequence(stream *clientStream) uint16 {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	stream.NextSequence++
	if stream.NextSequence == 0 {
		stream.NextSequence = 1
	}
	stream.LastActivityAt = time.Now()
	return stream.NextSequence
}

func (c *Client) sendStreamData(stream *clientStream, payload []byte, timeout time.Duration) error {
	if c == nil || stream == nil {
		return ErrClientStreamClosed
	}
	return c.sendStreamProtocolOneWay(
		Enums.PACKET_STREAM_DATA,
		stream.ID,
		c.nextClientStreamSequence(stream),
		payload,
		timeout,
	)
}

func (c *Client) sendStreamFIN(stream *clientStream, timeout time.Duration) error {
	if c == nil || stream == nil {
		return ErrClientStreamClosed
	}
	stream.mu.Lock()
	if stream.LocalFinSent || stream.Closed {
		stream.mu.Unlock()
		return nil
	}
	stream.LocalFinSent = true
	stream.mu.Unlock()

	return c.sendStreamProtocolOneWay(
		Enums.PACKET_STREAM_FIN,
		stream.ID,
		c.nextClientStreamSequence(stream),
		nil,
		timeout,
	)
}

func (c *Client) sendStreamRST(stream *clientStream, timeout time.Duration) error {
	if c == nil || stream == nil {
		return ErrClientStreamClosed
	}
	stream.mu.Lock()
	if stream.ResetSent || stream.Closed {
		stream.mu.Unlock()
		return nil
	}
	stream.ResetSent = true
	stream.mu.Unlock()

	return c.sendStreamProtocolOneWay(
		Enums.PACKET_STREAM_RST,
		stream.ID,
		c.nextClientStreamSequence(stream),
		nil,
		timeout,
	)
}

func (c *Client) handleFollowUpServerPacket(packet VpnProto.Packet, timeout time.Duration) error {
	current := packet
	for range maxClientStreamFollowUps {
		dispatch, err := c.dispatchServerPacket(current, timeout, nil)
		if err != nil {
			return err
		}
		if dispatch.stop || !dispatch.hasNext {
			return nil
		}
		current = dispatch.next
	}
	return nil
}

func (c *Client) handlePackedServerControlBlocks(payload []byte, timeout time.Duration) error {
	_, err := c.handlePackedServerControlBlocksForQueuedPacket(payload, timeout, nil)
	return err
}

func (c *Client) handlePackedServerControlBlocksForQueuedPacket(payload []byte, timeout time.Duration, sent *arq.QueuedPacket) (bool, error) {
	if len(payload) < arq.PackedControlBlockSize {
		return false, nil
	}
	c.cachePackedStreamControlReplies(payload)
	var firstErr error
	ackedSent := false
	arq.ForEachPackedControlBlock(payload, func(packetType uint8, streamID uint16, sequenceNum uint16, fragmentID uint8, totalFragments uint8) bool {
		if packetType == Enums.PACKET_PACKED_CONTROL_BLOCKS {
			return true
		}
		packet := VpnProto.Packet{
			PacketType:     packetType,
			StreamID:       streamID,
			HasStreamID:    streamID != 0,
			SequenceNum:    sequenceNum,
			HasSequenceNum: sequenceNum != 0,
			FragmentID:     fragmentID,
			TotalFragments: totalFragments,
		}
		dispatch, err := c.dispatchServerPacket(packet, timeout, sent)
		if dispatch.ackedQueued {
			ackedSent = true
		}
		if err != nil && firstErr == nil {
			firstErr = err
			return false
		}
		if dispatch.hasNext {
			if err := c.handleFollowUpServerPacket(dispatch.next, timeout); err != nil && firstErr == nil {
				firstErr = err
				return false
			}
		}
		return true
	})
	return ackedSent, firstErr
}

func matchesQueuedPacketAck(sent arq.QueuedPacket, packetType uint8, streamID uint16, sequenceNum uint16, fragmentID uint8, totalFragments uint8) bool {
	if sent.StreamID != 0 {
		if sent.StreamID != streamID || sent.SequenceNum != sequenceNum {
			return false
		}
		return matchesClientStreamAck(sent.PacketType, packetType)
	}
	if sent.PacketType != Enums.PACKET_DNS_QUERY_REQ || packetType != Enums.PACKET_DNS_QUERY_REQ_ACK {
		return false
	}
	if sent.SequenceNum != sequenceNum || sent.FragmentID != fragmentID {
		return false
	}
	expectedTotal := sent.TotalFragments
	if expectedTotal == 0 {
		expectedTotal = 1
	}
	if totalFragments == 0 {
		totalFragments = 1
	}
	return expectedTotal == totalFragments
}

func (c *Client) handleInboundStreamPacket(packet VpnProto.Packet, timeout time.Duration) (VpnProto.Packet, error) {
	stream, ok := c.getStream(packet.StreamID)
	if !ok || stream == nil {
		if closedResponse, handled, err := c.handleClosedStreamPacket(packet, timeout); handled {
			return closedResponse, err
		}
		if err := c.sendStreamProtocolOneWay(Enums.PACKET_STREAM_RST, packet.StreamID, packet.SequenceNum, nil, timeout); err != nil {
			return VpnProto.Packet{}, err
		}
		return VpnProto.Packet{}, nil
	}

	stream.mu.Lock()
	stream.LastActivityAt = time.Now()
	stream.mu.Unlock()

	switch packet.PacketType {
	case Enums.PACKET_STREAM_DATA:
		if c.log != nil && len(packet.Payload) != 0 {
			c.log.Debugf(
				"ðŸ“¥ <blue>Inbound Stream Data, Stream ID: <cyan>%d</cyan> | Seq: <cyan>%d</cyan> | Bytes: <cyan>%d</cyan></blue>",
				stream.ID,
				packet.SequenceNum,
				len(packet.Payload),
			)
		}
		c.noteStreamProgress(stream.ID)
		assembled, ready, completed := c.collectInboundStreamDataFragments(packet)
		if completed {
			return c.sendStreamAckOneWay(Enums.PACKET_STREAM_DATA_ACK, stream.ID, packet.SequenceNum)
		}
		if !ready {
			return VpnProto.Packet{}, nil
		}
		stream.mu.Lock()
		if !stream.InboundNextSet {
			stream.InboundNextSeq = 1
			stream.InboundNextSet = true
		}
		lastDelivered := stream.InboundNextSeq - 1
		if stream.InboundNextSeq == 0 {
			lastDelivered = 0xFFFF
		}
		if stream.InboundDataSet && streamutil.SequenceSeenOrOlder(lastDelivered, packet.SequenceNum) {
			stream.mu.Unlock()
			return c.sendStreamAckOneWay(Enums.PACKET_STREAM_DATA_ACK, stream.ID, packet.SequenceNum)
		}
		diff := uint16(packet.SequenceNum - stream.InboundNextSeq)
		if diff > uint16(stream.arqWindowSize) {
			stream.mu.Unlock()
			return VpnProto.Packet{}, nil
		}
		if stream.InboundPending == nil {
			stream.InboundPending = make(map[uint16][]byte, 8)
		}
		if _, exists := stream.InboundPending[packet.SequenceNum]; !exists {
			if len(stream.InboundPending) < stream.arqWindowSize {
				stream.InboundPending[packet.SequenceNum] = assembled
			}
		}
		readyPayloads := drainClientInboundReadyChunks(stream)
		shouldCloseAfterData := stream.RemoteFinSet && stream.InboundNextSet && stream.InboundNextSeq == stream.RemoteFinSeq
		stream.mu.Unlock()
		for _, readyPayload := range readyPayloads {
			if len(readyPayload) == 0 {
				continue
			}
			if _, err := stream.Conn.Write(readyPayload); err != nil {
				if c.log != nil {
					c.log.Warnf(
						"🧦 <yellow>Local Stream Write Failed, Stream ID: <cyan>%d</cyan> | Error: <cyan>%v</cyan></yellow>",
						stream.ID,
						err,
					)
				}
				stream.mu.Lock()
				stream.Closed = true
				stream.mu.Unlock()
				c.deleteStream(stream.ID)
				if err := c.sendStreamProtocolOneWay(Enums.PACKET_STREAM_RST, stream.ID, packet.SequenceNum, nil, timeout); err != nil {
					return VpnProto.Packet{}, err
				}
				return VpnProto.Packet{}, nil
			}
		}

		if shouldCloseAfterData {
			streamutil.CloseWrite(stream.Conn)
			if streamFinished(stream) {
				c.deleteStream(stream.ID)
			}
		}
		return c.sendStreamAckOneWay(Enums.PACKET_STREAM_DATA_ACK, stream.ID, packet.SequenceNum)
	case Enums.PACKET_STREAM_FIN:
		c.noteStreamProgress(stream.ID)
		stream.mu.Lock()
		if stream.RemoteFinSet && stream.RemoteFinSeq == packet.SequenceNum {
			stream.mu.Unlock()
			return c.sendStreamAckOneWay(Enums.PACKET_STREAM_FIN_ACK, stream.ID, packet.SequenceNum)
		}
		stream.RemoteFinSeq = packet.SequenceNum
		stream.RemoteFinSet = true
		stream.RemoteFinRecv = true

		shouldClose := stream.InboundNextSet && stream.InboundNextSeq == stream.RemoteFinSeq
		stream.mu.Unlock()

		if shouldClose {
			streamutil.CloseWrite(stream.Conn)
			if streamFinished(stream) {
				c.deleteStream(stream.ID)
			}
		}
		return c.sendStreamAckOneWay(Enums.PACKET_STREAM_FIN_ACK, stream.ID, packet.SequenceNum)
	case Enums.PACKET_STREAM_RST:
		c.noteStreamProgress(stream.ID)
		stream.mu.Lock()
		stream.Closed = true
		stream.mu.Unlock()
		c.deleteStream(stream.ID)
		return c.sendStreamAckOneWay(Enums.PACKET_STREAM_RST_ACK, stream.ID, packet.SequenceNum)
	default:
		return VpnProto.Packet{}, nil
	}
}

func (c *Client) sendStreamAckOneWay(packetType uint8, streamID uint16, sequenceNum uint16) (VpnProto.Packet, error) {
	if c == nil {
		return VpnProto.Packet{}, ErrClientStreamClosed
	}
	if c.log != nil {
		c.log.Debugf(
			"\U0001F4E8 <blue>Sending Stream ACK</blue> <magenta>|</magenta> <blue>Stream ID</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Packet</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan>",
			streamID,
			Enums.PacketTypeName(packetType),
			sequenceNum,
		)
	}
	err := c.sendStreamProtocolOneWay(packetType, streamID, sequenceNum, nil, defaultRuntimeTimeout)
	return VpnProto.Packet{}, err
}

func (c *Client) sendStreamProtocolOneWay(packetType uint8, streamID uint16, sequenceNum uint16, payload []byte, timeout time.Duration) error {
	if c == nil || streamID == 0 {
		return ErrClientStreamClosed
	}
	if !c.SessionReady() {
		return ErrTunnelDNSDispatchFailed
	}

	connections, err := c.selectTargetConnectionsForPacket(packetType, streamID)
	if err != nil {
		return err
	}

	packet := arq.QueuedPacket{
		PacketType:  packetType,
		StreamID:    streamID,
		SequenceNum: sequenceNum,
		Payload:     payload,
		Priority:    arq.DefaultPriorityForPacket(packetType),
	}
	deadline := time.Now().Add(normalizeTimeout(timeout, defaultRuntimeTimeout))
	return sendRuntimeQueuedPacketParallel(connections, ErrTunnelDNSDispatchFailed, func(connection Connection) error {
		return c.sendQueuedRuntimePacketWithConnection(connection, packet, deadline)
	})
}

func (c *Client) queueStreamPacket(stream *clientStream, packetType uint8, payload []byte) error {
	if c == nil || stream == nil {
		return ErrClientStreamClosed
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.Closed {
		return ErrClientStreamClosed
	}
	if packetType == Enums.PACKET_STREAM_FIN && stream.LocalFinSent {
		return nil
	}
	if packetType == Enums.PACKET_STREAM_RST && stream.ResetSent {
		return nil
	}
	if packetType == Enums.PACKET_STREAM_DATA && c.effectiveStreamTXQueueLimit() > 0 && len(stream.TXQueue)+len(stream.TXInFlight) >= c.effectiveStreamTXQueueLimit() {
		return ErrClientStreamBackpressure
	}

	stream.NextSequence++
	if stream.NextSequence == 0 {
		stream.NextSequence = 1
	}
	sequenceNum := stream.NextSequence
	stream.LastActivityAt = time.Now()
	if packetType == Enums.PACKET_STREAM_FIN {
		stream.LocalFinSent = true
		stream.LocalFinSeq = sequenceNum
		stream.LocalFinAcked = false
	}
	if packetType == Enums.PACKET_STREAM_RST {
		stream.ResetSent = true
		clearClientStreamDataLocked(stream)
	}

	// Optimization: Use Payload Pool for data packets to reduce allocations
	p := arq.AllocPayload(payload)

	packet := clientStreamTXPacket{
		PacketType:  packetType,
		SequenceNum: sequenceNum,
		Payload:     p,
		CreatedAt:   stream.LastActivityAt,
		RetryDelay:  streamRetryBaseLocked(stream),
	}
	stream.TXQueue = append(stream.TXQueue, packet)
	queueLen := len(stream.TXQueue)
	inFlightLen := len(stream.TXInFlight)
	notifyStreamWake(stream)
	if c.log != nil {
		c.log.Debugf(
			"ðŸ“¤ <blue>Queued Stream Packet, Stream ID: <cyan>%d</cyan> | Packet: <cyan>%s</cyan> | Seq: <cyan>%d</cyan> | Bytes: <cyan>%d</cyan> | Queue: <cyan>%d</cyan> | InFlight: <cyan>%d</cyan></blue>",
			stream.ID,
			Enums.PacketTypeName(packetType),
			sequenceNum,
			len(payload),
			queueLen,
			inFlightLen,
		)
	}
	return nil
}

func (c *Client) runClientStreamTXLoop(stream *clientStream, timeout time.Duration) {
	if c == nil || stream == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			if c.log != nil {
				c.log.Errorf(
					"ðŸ’¥ <red>Client Stream TX Loop Panic: <cyan>%v</cyan> (Stream ID: <cyan>%d</cyan>)</red>",
					recovered,
					stream.ID,
				)
			}
			_ = c.queueStreamPacket(stream, Enums.PACKET_STREAM_RST, nil)
			c.deleteStream(stream.ID)
		}
	}()
	timeout = normalizeTimeout(timeout, defaultRuntimeTimeout)

	// Optimization: Use a single reusable timer for the loop lifecycle
	waitTimer := time.NewTimer(time.Hour)
	if !waitTimer.Stop() {
		select {
		case <-waitTimer.C:
		default:
		}
	}
	defer waitTimer.Stop()

	for {
		if c.expireClientStreamTX(stream, time.Now()) {
			if streamFinished(stream) {
				c.deleteStream(stream.ID)
				return
			}
			continue
		}
		packet, waitFor, shouldStop := nextClientStreamTX(stream, c.effectiveStreamTXWindow())
		if shouldStop {
			return
		}
		if packet == nil {
			select {
			case <-stream.TXWake:
				continue
			case <-stream.StopCh:
				return
			}
		}
		if waitFor > 0 {
			waitTimer.Reset(waitFor)
			select {
			case <-waitTimer.C:
			case <-stream.TXWake:
				if !waitTimer.Stop() {
					select {
					case <-waitTimer.C:
					default:
					}
				}
				continue
			case <-stream.StopCh:
				return
			}
		}

		if c.stream0Runtime == nil || !c.stream0Runtime.IsRunning() {
			packetType := packet.PacketType
			if packetType == Enums.PACKET_STREAM_DATA && packet.RetryCount > 0 {
				packetType = Enums.PACKET_STREAM_RESEND
			}
			sentAt := time.Now()
			if err := c.sendStreamProtocolOneWay(packetType, stream.ID, packet.SequenceNum, packet.Payload, timeout); err != nil {
				rescheduleClientStreamTX(stream, packet.SequenceNum)
				continue
			}
			armClientStreamTXRetry(c, stream.ID, packet.SequenceNum, sentAt)
			if streamFinished(stream) {
				c.deleteStream(stream.ID)
				return
			}
			continue
		}
		if !markClientStreamTXScheduled(stream, packet.SequenceNum) {
			continue
		}
		packetType := packet.PacketType
		if packetType == Enums.PACKET_STREAM_DATA && packet.RetryCount > 0 {
			packetType = Enums.PACKET_STREAM_RESEND
		}
		if c.log != nil {
			c.log.Debugf(
				"ðŸ“¤ <blue>Dispatching Stream Packet, Stream ID: <cyan>%d</cyan> | Packet: <cyan>%s</cyan> | Seq: <cyan>%d</cyan> | Retry: <cyan>%d</cyan> | Bytes: <cyan>%d</cyan></blue>",
				stream.ID,
				Enums.PacketTypeName(packetType),
				packet.SequenceNum,
				packet.RetryCount,
				len(packet.Payload),
			)
		}
	if !c.stream0Runtime.QueueStreamPacket(stream.ID, packetType, packet.SequenceNum, packet.Payload) {
			rescheduleClientStreamTX(stream, packet.SequenceNum)
			time.Sleep(25 * time.Millisecond)
			continue
		}
	}
}

func nextClientStreamTX(stream *clientStream, windowSize int) (*clientStreamTXPacket, time.Duration, bool) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.Closed {
		return nil, 0, true
	}
	if windowSize < 1 {
		windowSize = 1
	}
	now := time.Now()
	for len(stream.TXInFlight) < windowSize && len(stream.TXQueue) != 0 {
		packet := stream.TXQueue[0]
		stream.TXQueue[0] = clientStreamTXPacket{}
		stream.TXQueue = stream.TXQueue[1:]
		if packet.RetryDelay <= 0 {
			packet.RetryDelay = streamRetryBaseLocked(stream)
		}
		packet.RetryAt = now
		packet.Scheduled = false
		stream.TXInFlight = append(stream.TXInFlight, packet)
		if stream.log != nil {
			stream.log.Debugf("ðŸ“¤ <blue>TX Move to InFlight, Stream ID: <cyan>%d</cyan> | Seq: <cyan>%d</cyan> | InFlight: <cyan>%d/%d</cyan></blue>", stream.ID, packet.SequenceNum, len(stream.TXInFlight), windowSize)
		}
	}
	if len(stream.TXInFlight) == 0 {
		return nil, 0, false
	}

	selectedIdx := -1
	minWait := time.Duration(-1)
	for idx := range stream.TXInFlight {
		if stream.TXInFlight[idx].Scheduled {
			continue
		}
		waitFor := time.Until(stream.TXInFlight[idx].RetryAt)
		if waitFor <= 0 {
			selectedIdx = idx
			minWait = 0
			break
		}
		if minWait < 0 || waitFor < minWait {
			minWait = waitFor
		}
	}
	if selectedIdx < 0 {
		return nil, minWait, false
	}
	packet := stream.TXInFlight[selectedIdx]
	return &packet, minWait, false
}

func rescheduleClientStreamTX(stream *clientStream, sequenceNum uint16) {
	if stream == nil {
		return
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	for idx := range stream.TXInFlight {
		if stream.TXInFlight[idx].SequenceNum != sequenceNum {
			continue
		}
		delay := stream.TXInFlight[idx].RetryDelay
		if delay <= 0 {
			delay = streamRetryBaseLocked(stream)
		}
		stream.TXInFlight[idx].Scheduled = false
		stream.TXInFlight[idx].RetryAt = time.Now().Add(delay)
		stream.TXInFlight[idx].RetryCount++
		delay *= 2
		if delay > streamTXMaxRetryDelay {
			delay = streamTXMaxRetryDelay
		}
		stream.TXInFlight[idx].RetryDelay = delay
		if stream.log != nil {
			stream.log.Debugf("ðŸ”„ <yellow>TX Rescheduled, Stream ID: <cyan>%d</cyan> | Seq: <cyan>%d</cyan> | Retry: <cyan>%d</cyan></yellow>", stream.ID, sequenceNum, stream.TXInFlight[idx].RetryCount)
		}
		return
	}
}

func armClientStreamTXRetry(c *Client, streamID uint16, sequenceNum uint16, sentAt time.Time) {
	if c == nil || streamID == 0 {
		return
	}
	stream, ok := c.getStream(streamID)
	if !ok || stream == nil {
		return
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	for idx := range stream.TXInFlight {
		if stream.TXInFlight[idx].SequenceNum != sequenceNum {
			continue
		}
		delay := stream.TXInFlight[idx].RetryDelay
		if delay <= 0 {
			delay = streamRetryBaseLocked(stream)
		}
		stream.TXInFlight[idx].Scheduled = false
		stream.TXInFlight[idx].LastSentAt = sentAt
		stream.TXInFlight[idx].RetryAt = sentAt.Add(delay)
		return
	}
}

func markClientStreamTXScheduled(stream *clientStream, sequenceNum uint16) bool {
	if stream == nil {
		return false
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	for idx := range stream.TXInFlight {
		if stream.TXInFlight[idx].SequenceNum != sequenceNum {
			continue
		}
		if stream.TXInFlight[idx].Scheduled {
			return false
		}
		stream.TXInFlight[idx].Scheduled = true
		stream.TXInFlight[idx].LastSentAt = time.Now()
		return true
	}
	return false
}

func ackClientStreamTX(stream *clientStream, sequenceNum uint16, ackedAt time.Time) {
	ackClientStreamTXWithLog(nil, stream, sequenceNum, ackedAt)
}

func logClientStreamACK(c *Client, stream *clientStream, packetType uint8, sequenceNum uint16, payloadLen int) {
	if c == nil || c.log == nil || stream == nil {
		return
	}
	c.log.Debugf(
		"âœ… <green>Stream Packet ACKed, Stream ID: <cyan>%d</cyan> | Packet: <cyan>%s</cyan> | Seq: <cyan>%d</cyan> | Bytes: <cyan>%d</cyan></green>",
		stream.ID,
		Enums.PacketTypeName(packetType),
		sequenceNum,
		payloadLen,
	)
}

func ackClientStreamTXWithLog(c *Client, stream *clientStream, sequenceNum uint16, ackedAt time.Time) {
	if stream == nil {
		return
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	for idx := range stream.TXInFlight {
		if stream.TXInFlight[idx].SequenceNum != sequenceNum {
			continue
		}
		packetType := stream.TXInFlight[idx].PacketType
		payloadLen := len(stream.TXInFlight[idx].Payload)
		updateClientStreamRTO(stream, stream.TXInFlight[idx], ackedAt)
		// Release payload back to pool
		if stream.TXInFlight[idx].Payload != nil {
			arq.FreePayload(stream.TXInFlight[idx].Payload)
		}
		copy(stream.TXInFlight[idx:], stream.TXInFlight[idx+1:])
		lastIdx := len(stream.TXInFlight) - 1
		stream.TXInFlight[lastIdx] = clientStreamTXPacket{}
		stream.TXInFlight = stream.TXInFlight[:lastIdx]
		logClientStreamACK(c, stream, packetType, sequenceNum, payloadLen)
		return
	}
}

func ackClientStreamTXByResponse(stream *clientStream, sentPacketType uint8, response VpnProto.Packet, ackedAt time.Time) bool {
	if stream == nil {
		return false
	}
	if !matchesClientStreamAck(sentPacketType, response.PacketType) {
		return false
	}
	if response.StreamID != stream.ID {
		return false
	}
	ackClientStreamTX(stream, response.SequenceNum, ackedAt)
	return true
}

func notifyStreamWake(stream *clientStream) {
	if stream == nil {
		return
	}
	select {
	case stream.TXWake <- struct{}{}:
	default:
	}
}

func (c *Client) runLocalStreamReadLoop(stream *clientStream, timeout time.Duration) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if c.log != nil {
				c.log.Errorf(
					"ðŸ’¥ <red>Client Stream Read Loop Panic: <cyan>%v</cyan> (Stream ID: <cyan>%d</cyan>)</red>",
					recovered,
					stream.ID,
				)
			}
			_ = c.queueStreamPacket(stream, Enums.PACKET_STREAM_RST, nil)
		}
	}()
	defer func() {
		stream.mu.Lock()
		closed := stream.Closed
		stream.mu.Unlock()
		if !closed {
			_ = c.queueStreamPacket(stream, Enums.PACKET_STREAM_FIN, nil)
		}
		if streamFinished(stream) {
			c.deleteStream(stream.ID)
		}
	}()

	readSize := c.maxMainStreamFragmentPayload(c.cfg.Domains[0], Enums.PACKET_STREAM_DATA)
	if readSize < 256 {
		readSize = 256
	}
	buffer := make([]byte, readSize)
	for {
		n, err := stream.Conn.Read(buffer)
		if n > 0 {
			if c.log != nil {
				c.log.Debugf(
					"📂 <blue>Local Stream Read, Stream ID: <cyan>%d</cyan> | Bytes: <cyan>%d</cyan></blue>",
					stream.ID,
					n,
				)
			}
			if sendErr := c.queueStreamPacket(stream, Enums.PACKET_STREAM_DATA, buffer[:n]); sendErr != nil {
				if c.log != nil {
					c.log.Warnf(
						"📂 <yellow>Local Stream Queue Failed, Stream ID: <cyan>%d</cyan> | Error: <cyan>%v</cyan></yellow>",
						stream.ID,
						sendErr,
					)
				}
				_ = c.queueStreamPacket(stream, Enums.PACKET_STREAM_RST, nil)
				return
			}
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			return
		}
		_ = c.queueStreamPacket(stream, Enums.PACKET_STREAM_RST, nil)
		return
	}
}

func streamFinished(stream *clientStream) bool {
	if stream == nil {
		return true
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.Closed {
		return true
	}
	if stream.ResetSent {
		return false
	}
	if !stream.LocalFinSent || !stream.LocalFinAcked || !stream.RemoteFinRecv {
		return false
	}
	return len(stream.TXQueue) == 0 && len(stream.TXInFlight) == 0
}

func matchesClientStreamAck(sentType uint8, ackType uint8) bool {
	switch sentType {
	case Enums.PACKET_STREAM_DATA:
		return ackType == Enums.PACKET_STREAM_DATA_ACK
	case Enums.PACKET_STREAM_FIN:
		return ackType == Enums.PACKET_STREAM_FIN_ACK
	case Enums.PACKET_STREAM_RST:
		return ackType == Enums.PACKET_STREAM_RST_ACK
	default:
		return false
	}
}

func (c *Client) effectiveStreamTXWindow() int {
	if c == nil || c.streamTXWindow < 1 {
		return 1
	}
	if c.streamTXWindow > 32 {
		return 32
	}
	return c.streamTXWindow
}

func (c *Client) effectiveStreamTXQueueLimit() int {
	if c == nil || c.streamTXQueueLimit < 1 {
		return 128
	}
	if c.streamTXQueueLimit > 4096 {
		return 4096
	}
	return c.streamTXQueueLimit
}

func (c *Client) effectiveStreamTXMaxRetries() int {
	if c == nil || c.streamTXMaxRetries < 1 {
		return 24
	}
	if c.streamTXMaxRetries > 512 {
		return 512
	}
	return c.streamTXMaxRetries
}

func (c *Client) effectiveStreamTXTTL() time.Duration {
	if c == nil || c.streamTXTTL <= 0 {
		return 120 * time.Second
	}
	return c.streamTXTTL
}

func clearClientStreamDataLocked(stream *clientStream) {
	if stream == nil {
		return
	}
	if len(stream.TXQueue) != 0 {
		filteredQueue := stream.TXQueue[:0]
		for _, packet := range stream.TXQueue {
			if packet.PacketType == Enums.PACKET_STREAM_RST {
				filteredQueue = append(filteredQueue, packet)
			} else if packet.Payload != nil {
				arq.FreePayload(packet.Payload)
			}
		}
		for idx := len(filteredQueue); idx < len(stream.TXQueue); idx++ {
			stream.TXQueue[idx] = clientStreamTXPacket{}
		}
		stream.TXQueue = filteredQueue
	}
	if len(stream.TXInFlight) != 0 {
		filteredInFlight := stream.TXInFlight[:0]
		for _, packet := range stream.TXInFlight {
			if packet.PacketType == Enums.PACKET_STREAM_RST {
				filteredInFlight = append(filteredInFlight, packet)
			} else if packet.Payload != nil {
				arq.FreePayload(packet.Payload)
			}
		}
		for idx := len(filteredInFlight); idx < len(stream.TXInFlight); idx++ {
			stream.TXInFlight[idx] = clientStreamTXPacket{}
		}
		stream.TXInFlight = filteredInFlight
	}
}

func (c *Client) expireClientStreamTX(stream *clientStream, now time.Time) bool {
	if c == nil || stream == nil {
		return false
	}

	stream.mu.Lock()
	defer stream.mu.Unlock()

	if stream.Closed || len(stream.TXInFlight) == 0 {
		return false
	}

	maxRetries := c.effectiveStreamTXMaxRetries()
	ttl := c.effectiveStreamTXTTL()
	for _, packet := range stream.TXInFlight {
		if packet.RetryCount < maxRetries && now.Sub(packet.CreatedAt) < ttl {
			continue
		}

		if packet.PacketType == Enums.PACKET_STREAM_RST || stream.ResetSent {
			stream.Closed = true
			clearClientStreamDataLocked(stream)
			return true
		}

		stream.ResetSent = true
		clearClientStreamDataLocked(stream)
		stream.NextSequence++
		if stream.NextSequence == 0 {
			stream.NextSequence = 1
		}
		stream.TXQueue = append(stream.TXQueue, clientStreamTXPacket{
			PacketType:  Enums.PACKET_STREAM_RST,
			SequenceNum: stream.NextSequence,
			CreatedAt:   now,
			RetryDelay:  streamRetryBaseLocked(stream),
		})
		notifyStreamWake(stream)
		return true
	}

	return false
}

func streamRetryBaseLocked(stream *clientStream) time.Duration {
	if stream == nil || stream.retryBase <= 0 {
		return streamTXInitialRetryDelay
	}
	if stream.retryBase < streamTXMinRetryDelay {
		return streamTXMinRetryDelay
	}
	if stream.retryBase > streamTXMaxRetryDelay {
		return streamTXMaxRetryDelay
	}
	return stream.retryBase
}

func updateClientStreamRTO(stream *clientStream, packet clientStreamTXPacket, ackedAt time.Time) {
	if stream == nil || packet.RetryCount != 0 || packet.LastSentAt.IsZero() {
		return
	}
	sample := ackedAt.Sub(packet.LastSentAt)
	if sample <= 0 {
		return
	}
	if sample < streamTXMinRetryDelay {
		sample = streamTXMinRetryDelay
	}
	if sample > streamTXMaxRetryDelay {
		sample = streamTXMaxRetryDelay
	}
	if stream.srtt <= 0 {
		stream.srtt = sample
		stream.rttVar = sample / 2
	} else {
		diff := stream.srtt - sample
		if diff < 0 {
			diff = -diff
		}
		stream.rttVar = (3*stream.rttVar + diff) / 4
		stream.srtt = (7*stream.srtt + sample) / 8
	}
	rto := stream.srtt + 4*stream.rttVar
	if rto < streamTXMinRetryDelay {
		rto = streamTXMinRetryDelay
	}
	if rto > streamTXMaxRetryDelay {
		rto = streamTXMaxRetryDelay
	}
	stream.retryBase = rto
}

