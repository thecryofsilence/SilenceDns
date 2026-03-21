// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"errors"
	"fmt"
	"time"

	"masterdnsvpn-go/internal/arq"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

var ErrStreamHandshakeFailed = errors.New("stream handshake failed")

const (
	streamControlRetryBaseDelay      = 800 * time.Millisecond
	streamControlRetryMaxDelay       = 2500 * time.Millisecond
	streamControlHarvestInterval     = 200 * time.Millisecond
	streamControlInitialHarvestDelay = 120 * time.Millisecond
	streamControlHarvestTimeout      = 250 * time.Millisecond
	streamControlPongSleep           = 25 * time.Millisecond
	streamControlPongSleepMax        = 120 * time.Millisecond
	streamControlMaxPolls            = 24
)

func (c *Client) nextStreamID() uint16 {
	if c == nil {
		return 1
	}
	c.lastStreamID++
	if c.lastStreamID == 0 {
		c.lastStreamID = 1
	}
	return c.lastStreamID
}

func (c *Client) OpenSOCKS5Stream(targetPayload []byte, timeout time.Duration) (uint16, error) {
	if c == nil {
		return 0, ErrStreamHandshakeFailed
	}
	if !c.SessionReady() {
		return 0, ErrSessionInitFailed
	}
	if len(targetPayload) == 0 {
		return 0, ErrStreamHandshakeFailed
	}
	timeout = normalizeTimeout(timeout, defaultRuntimeTimeout)
	targetText := formatSOCKS5TargetPayload(targetPayload)

	streamID := c.nextStreamID()
	if c.log != nil {
		c.log.Infof(
			"🧦 <green>New Local SOCKS5 Connection, Stream ID: <cyan>%d</cyan> | Target: <cyan>%s</cyan></green>",
			streamID,
			targetText,
		)
	}
	synPacket, err := c.exchangeStreamControlPacket(Enums.PACKET_STREAM_SYN, streamID, 1, nil, timeout)
	if err != nil {
		if c.log != nil {
			c.log.Debugf(
				"🧦 <yellow>STREAM_SYN Failed, Stream ID: <cyan>%d</cyan> | Target: <cyan>%s</cyan> | Error: <cyan>%v</cyan></yellow>",
				streamID,
				targetText,
				err,
			)
		}
		return 0, err
	}
	if synPacket.PacketType != Enums.PACKET_STREAM_SYN_ACK || synPacket.StreamID != streamID {
		if c.log != nil {
			c.log.Debugf(
				"🧦 <yellow>STREAM_SYN Unexpected Reply, Stream ID: <cyan>%d</cyan> | Got: <cyan>%s</cyan></yellow>",
				streamID,
				Enums.PacketTypeName(synPacket.PacketType),
			)
		}
		return 0, ErrStreamHandshakeFailed
	}
	if c.log != nil {
		c.log.Debugf(
			"🧦 <green>STREAM_SYN Acknowledged, Stream ID: <cyan>%d</cyan></green>",
			streamID,
		)
	}

	socksPacket, err := c.exchangeStreamControlPacket(Enums.PACKET_SOCKS5_SYN, streamID, 2, targetPayload, timeout)
	if err != nil {
		if c.log != nil {
			c.log.Debugf(
				"🧦 <yellow>SOCKS5_SYN Failed, Stream ID: <cyan>%d</cyan> | Target: <cyan>%s</cyan> | Error: <cyan>%v</cyan></yellow>",
				streamID,
				targetText,
				err,
			)
		}
		return 0, err
	}
	if socksPacket.StreamID != streamID {
		if c.log != nil {
			c.log.Debugf(
				"🧦 <yellow>SOCKS5_SYN Reply Stream Mismatch, Stream ID: <cyan>%d</cyan> | Got: <cyan>%d</cyan></yellow>",
				streamID,
				socksPacket.StreamID,
			)
		}
		return 0, ErrStreamHandshakeFailed
	}
	if socksPacket.PacketType == Enums.PACKET_SOCKS5_SYN_ACK {
		if c.log != nil {
			c.log.Infof(
				"🧦 <green>SOCKS5 Handshake Completed, Stream ID: <cyan>%d</cyan> | Target: <cyan>%s</cyan></green>",
				streamID,
				targetText,
			)
		}
		return streamID, nil
	}
	if isSOCKS5ErrorPacket(socksPacket.PacketType) {
		if c.log != nil {
			c.log.Debugf(
				"🧦 <yellow>SOCKS5 Target Rejected, Stream ID: <cyan>%d</cyan> | Target: <cyan>%s</cyan> | Packet: <cyan>%s</cyan></yellow>",
				streamID,
				targetText,
				Enums.PacketTypeName(socksPacket.PacketType),
			)
		}
		return 0, fmt.Errorf("%w: %s", ErrStreamHandshakeFailed, Enums.PacketTypeName(socksPacket.PacketType))
	}
	if c.log != nil {
		c.log.Debugf(
			"🧦 <yellow>SOCKS5_SYN Unexpected Reply, Stream ID: <cyan>%d</cyan> | Target: <cyan>%s</cyan> | Got: <cyan>%s</cyan></yellow>",
			streamID,
			targetText,
			Enums.PacketTypeName(socksPacket.PacketType),
		)
	}
	return 0, ErrStreamHandshakeFailed
}

func (c *Client) OpenTCPStream(timeout time.Duration) (uint16, error) {
	if c == nil {
		return 0, ErrStreamHandshakeFailed
	}
	if !c.SessionReady() {
		return 0, ErrSessionInitFailed
	}
	timeout = normalizeTimeout(timeout, defaultRuntimeTimeout)

	streamID := c.nextStreamID()
	synPacket, err := c.exchangeStreamControlPacket(
		Enums.PACKET_STREAM_SYN,
		streamID,
		1,
		VpnProto.TCPForwardSynPayload(),
		timeout,
	)
	if err != nil {
		return 0, err
	}
	if synPacket.PacketType != Enums.PACKET_STREAM_SYN_ACK || synPacket.StreamID != streamID {
		return 0, ErrStreamHandshakeFailed
	}
	return streamID, nil
}

func (c *Client) exchangeStreamControlPacket(packetType uint8, streamID uint16, sequenceNum uint16, payload []byte, timeout time.Duration) (VpnProto.Packet, error) {
	if c == nil {
		return VpnProto.Packet{}, ErrStreamHandshakeFailed
	}
	timeout = normalizeTimeout(timeout, defaultRuntimeTimeout)
	deadline := time.Now().Add(timeout)
	lastErr := error(ErrStreamHandshakeFailed)
	defer c.clearStreamControlState(packetType, streamID, sequenceNum)

	for {
		if cachedPacket, ok := c.takeExpectedStreamControlReply(packetType, streamID, sequenceNum); ok {
			return cachedPacket, nil
		}
		now := time.Now()
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return VpnProto.Packet{}, lastErr
		}
		state := c.getOrCreateStreamControlState(packetType, streamID, sequenceNum, now)
		if state.retryAt.After(now) {
			packet, ok, waitErr := c.awaitExpectedStreamControlReply(packetType, streamID, sequenceNum, deadline)
			if waitErr == nil && ok {
				return packet, nil
			}
			if waitErr != nil {
				lastErr = waitErr
			}
			if !shouldRetryStreamControlPacket(packetType) {
				return VpnProto.Packet{}, lastErr
			}
			continue
		}

		connections, err := c.selectTargetConnectionsForPacket(packetType, streamID)
		if err != nil {
			if c.log != nil {
				c.log.Debugf(
					"🧦 <yellow>Stream Control Connection Selection Failed, Stream ID: <cyan>%d</cyan> | Packet: <cyan>%s</cyan> | Error: <cyan>%v</cyan></yellow>",
					streamID,
					Enums.PacketTypeName(packetType),
					err,
				)
			}
			lastErr = err
		} else {
			state = c.noteStreamControlSend(packetType, streamID, sequenceNum, now)
			if c.log != nil {
				c.log.Debugf(
					"🧦 <blue>Sending Stream Control Packet, Stream ID: <cyan>%d</cyan> | Packet: <cyan>%s</cyan> | Targets: <cyan>%d</cyan> | Attempt: <cyan>%d</cyan></blue>",
					streamID,
					Enums.PacketTypeName(packetType),
					len(connections),
					state.retryCount,
				)
			}
			if err := c.sendStreamControlPacketOneWay(packetType, streamID, sequenceNum, payload, connections, remaining); err == nil {
				if c.log != nil {
					c.log.Debugf("🧦 <blue>Handshake Packet Sent, Awaiting Reply, Stream ID: <cyan>%d</cyan> | Packet: <cyan>%s</cyan></blue>", streamID, Enums.PacketTypeName(packetType))
				}
				packet, ok, waitErr := c.awaitExpectedStreamControlReply(packetType, streamID, sequenceNum, deadline)
				if waitErr == nil && ok {
					return packet, nil
				}
				if waitErr != nil {
					lastErr = waitErr
				} else if !ok {
					lastErr = ErrStreamHandshakeFailed
				}
			} else {
				lastErr = err
			}
		}

		if !shouldRetryStreamControlPacket(packetType) {
			return VpnProto.Packet{}, lastErr
		}
	}
}

func (c *Client) sendStreamControlPacketOneWay(packetType uint8, streamID uint16, sequenceNum uint16, payload []byte, connections []Connection, timeout time.Duration) error {
	if c == nil {
		return ErrStreamHandshakeFailed
	}
	timeout = normalizeTimeout(timeout, defaultRuntimeTimeout)
	var err error
	if len(connections) == 0 {
		connections, err = c.selectTargetConnectionsForPacket(packetType, streamID)
	} else {
		connections, err = c.runtimeConnections(connections)
	}
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
	deadline := time.Now().Add(timeout)
	return sendRuntimeQueuedPacketParallel(connections, ErrStreamHandshakeFailed, func(connection Connection) error {
		return c.sendQueuedRuntimePacketWithConnection(connection, packet, deadline)
	})
}

func (c *Client) awaitExpectedStreamControlReply(sentType uint8, streamID uint16, sequenceNum uint16, deadline time.Time) (VpnProto.Packet, bool, error) {
	if c == nil {
		return VpnProto.Packet{}, false, ErrStreamHandshakeFailed
	}
	pollIdx := 0
	for {
		if cachedPacket, ok := c.takeExpectedStreamControlReply(sentType, streamID, sequenceNum); ok {
			if c.log != nil {
				c.log.Debugf("🧦 <green>Handshake Reply Found in Cache, Stream ID: <cyan>%d</cyan> | Packet: <cyan>%s</cyan> | Poll: <cyan>%d</cyan></green>", streamID, Enums.PacketTypeName(cachedPacket.PacketType), pollIdx)
			}
			return cachedPacket, true, nil
		}
		now := time.Now()
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return VpnProto.Packet{}, false, ErrStreamHandshakeFailed
		}
		if retryAt, ok := c.streamControlRetryAt(sentType, streamID, sequenceNum); ok && !retryAt.After(now) {
			return VpnProto.Packet{}, false, nil
		}
		if c.log != nil && pollIdx > 0 && pollIdx%8 == 0 {
			c.log.Warnf(
				"🧦 <yellow>Handshake Poll Still Waiting, Stream ID: <cyan>%d</cyan> | Waiting For: <cyan>%s</cyan> | Poll: <cyan>%d</cyan> | Remaining: <cyan>%s</cyan></yellow>",
				streamID,
				Enums.PacketTypeName(sentType),
				pollIdx,
				remaining.Round(time.Millisecond),
			)
		}
		nextWake := remaining
		if retryAt, ok := c.streamControlRetryAt(sentType, streamID, sequenceNum); ok {
			retryWait := time.Until(retryAt)
			if retryWait > 0 && retryWait < nextWake {
				nextWake = retryWait
			}
		}
		if nextHarvestAt, ok := c.streamControlNextHarvestAt(sentType, streamID, sequenceNum); ok && nextHarvestAt.After(now) {
			harvestWait := nextHarvestAt.Sub(now)
			if harvestWait > 0 && harvestWait < nextWake {
				nextWake = harvestWait
			}
		}
		if nextWake > 0 {
			time.Sleep(nextWake)
		}
		if cachedPacket, ok := c.takeExpectedStreamControlReply(sentType, streamID, sequenceNum); ok {
			if c.log != nil {
				c.log.Debugf("ðŸ§¦ <green>Handshake Reply Found in Cache, Stream ID: <cyan>%d</cyan> | Packet: <cyan>%s</cyan> | Poll: <cyan>%d</cyan></green>", streamID, Enums.PacketTypeName(cachedPacket.PacketType), pollIdx)
			}
			return cachedPacket, true, nil
		}
		now = time.Now()
		if retryAt, ok := c.streamControlRetryAt(sentType, streamID, sequenceNum); ok && !retryAt.After(now) {
			return VpnProto.Packet{}, false, nil
		}
		if nextHarvestAt, ok := c.streamControlNextHarvestAt(sentType, streamID, sequenceNum); ok && nextHarvestAt.After(now) {
			continue
		}
		waitFor := streamControlHarvestTimeout
		remaining = time.Until(deadline)
		if waitFor > remaining {
			waitFor = remaining
		}
		if waitFor <= 0 {
			return VpnProto.Packet{}, false, ErrStreamHandshakeFailed
		}
		c.noteStreamControlHarvest(sentType, streamID, sequenceNum, now)
		packet, err := c.sendSessionControlPacket(Enums.PACKET_PING, buildMustClientPingPayload(), nil, waitFor)
		if err != nil {
			return VpnProto.Packet{}, false, err
		}
		pollIdx++
		if c.log != nil && packet.PacketType != Enums.PACKET_PONG {
			c.log.Debugf(
				"🧦 <blue>Stream Control Harvest Reply, Stream ID: <cyan>%d</cyan> | Waiting For: <cyan>%s</cyan> | Got: <cyan>%s</cyan></blue>",
				streamID,
				Enums.PacketTypeName(sentType),
				Enums.PacketTypeName(packet.PacketType),
			)
		}
		if matchesExpectedStreamResponse(sentType, streamID, sequenceNum, packet) {
			if c.log != nil {
				c.log.Debugf("🧦 <green>Handshake Reply Received via PING, Stream ID: <cyan>%d</cyan> | Packet: <cyan>%s</cyan> | Poll: <cyan>%d</cyan></green>", streamID, Enums.PacketTypeName(packet.PacketType), pollIdx)
			}
			return packet, true, nil
		}
		if err := c.handleAsyncServerPacket(packet, remaining); err != nil {
			return VpnProto.Packet{}, false, err
		}
	}
}

func (c *Client) harvestServerReplies(timeout time.Duration) error {
	if c == nil {
		return ErrStreamHandshakeFailed
	}
	packet, err := c.sendSessionControlPacket(Enums.PACKET_PING, buildMustClientPingPayload(), nil, timeout)
	if err != nil {
		return err
	}
	if c.log != nil && packet.PacketType != Enums.PACKET_PONG {
		c.log.Debugf(
			"ðŸ§¦ <blue>Stream Control Harvest Reply | Got: <cyan>%s</cyan></blue>",
			Enums.PacketTypeName(packet.PacketType),
		)
	}
	return c.handleAsyncServerPacket(packet, timeout)
}

func buildMustClientPingPayload() []byte {
	payload, err := buildClientPingPayload()
	if err != nil {
		return []byte{'P', 'O', ':', 0, 0, 0, 0}
	}
	return payload
}

func (c *Client) sendStreamControlPacketWithConnection(connection Connection, packetType uint8, streamID uint16, sequenceNum uint16, payload []byte, timeout time.Duration) (VpnProto.Packet, error) {
	return c.sendFragmentedStreamPacketWithConnection(connection, packetType, streamID, sequenceNum, payload, timeout, ErrStreamHandshakeFailed)
}

func (c *Client) sendFragmentedStreamPacketWithConnection(connection Connection, packetType uint8, streamID uint16, sequenceNum uint16, payload []byte, timeout time.Duration, fallbackErr error) (VpnProto.Packet, error) {
	fragments, err := c.fragmentMainStreamPayload(connection.Domain, packetType, payload)
	if err != nil {
		return VpnProto.Packet{}, err
	}
	deadline := time.Now().Add(timeout)

	for fragmentID, fragmentPayload := range fragments {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return VpnProto.Packet{}, fallbackErr
		}
		query, err := c.buildStreamQuery(
			connection.Domain,
			packetType,
			streamID,
			sequenceNum,
			uint8(fragmentID),
			uint8(len(fragments)),
			fragmentPayload,
		)
		if err != nil {
			return VpnProto.Packet{}, err
		}

		packet, err := c.exchangeDNSOverConnection(connection, query, remaining)
		if err != nil {
			if c.log != nil {
				c.log.Debugf(
					"🧦 <yellow>Stream Control Exchange Failed, Stream ID: <cyan>%d</cyan> | Packet: <cyan>%s</cyan> | Resolver: <cyan>%s</cyan> | Error: <cyan>%v</cyan></yellow>",
					streamID,
					Enums.PacketTypeName(packetType),
					connection.ResolverLabel,
					err,
				)
			}
			return VpnProto.Packet{}, err
		}
		if c.log != nil {
			c.log.Debugf(
				"🧦 <blue>Stream Control Reply Received, Stream ID: <cyan>%d</cyan> | Sent: <cyan>%s</cyan> | Got: <cyan>%s</cyan> | Resolver: <cyan>%s</cyan></blue>",
				streamID,
				Enums.PacketTypeName(packetType),
				Enums.PacketTypeName(packet.PacketType),
				connection.ResolverLabel,
			)
		}

		if fragmentID < len(fragments)-1 {
			if err := c.handleAsyncServerPacket(packet, remaining); err != nil {
				if c.log != nil {
					c.log.Debugf(
						"🧦 <yellow>Intermediate Fragment Reply Handling Failed, Stream ID: <cyan>%d</cyan> | Packet: <cyan>%s</cyan> | Error: <cyan>%v</cyan></yellow>",
						streamID,
						Enums.PacketTypeName(packetType),
						err,
					)
				}
				return VpnProto.Packet{}, err
			}
			if cachedPacket, ok := c.takeExpectedStreamControlReply(packetType, streamID, sequenceNum); ok {
				return cachedPacket, nil
			}
			continue
		}
		pollCount := 0
		pongSleep := streamControlPongSleep
		for {
			if matchesExpectedStreamResponse(packetType, streamID, sequenceNum, packet) {
				return packet, nil
			}
			if err := c.handleAsyncServerPacket(packet, time.Until(deadline)); err != nil {
				if c.log != nil {
					c.log.Debugf(
						"🧦 <yellow>Unexpected Reply Handling Failed, Stream ID: <cyan>%d</cyan> | Sent: <cyan>%s</cyan> | Got: <cyan>%s</cyan> | Error: <cyan>%v</cyan></yellow>",
						streamID,
						Enums.PacketTypeName(packetType),
						Enums.PacketTypeName(packet.PacketType),
						err,
					)
				}
				return VpnProto.Packet{}, err
			}
			remaining = time.Until(deadline)
			if remaining <= 0 {
				if c.log != nil {
					c.log.Debugf(
						"🧦 <yellow>Stream Control Timed Out Waiting For Expected Reply, Stream ID: <cyan>%d</cyan> | Packet: <cyan>%s</cyan></yellow>",
						streamID,
						Enums.PacketTypeName(packetType),
					)
				}
				return VpnProto.Packet{}, fallbackErr
			}
			if cachedPacket, ok := c.takeExpectedStreamControlReply(packetType, streamID, sequenceNum); ok {
				return cachedPacket, nil
			}
			if pollCount >= streamControlMaxPolls {
				if c.log != nil {
					c.log.Debugf(
						"ðŸ§¦ <yellow>Stream Control Follow-up Poll Limit Reached, Stream ID: <cyan>%d</cyan> | Packet: <cyan>%s</cyan> | Last: <cyan>%s</cyan></yellow>",
						streamID,
						Enums.PacketTypeName(packetType),
						Enums.PacketTypeName(packet.PacketType),
					)
				}
				return VpnProto.Packet{}, fallbackErr
			}
			packet, err = c.pollServerPacketWithConnection(connection, remaining)
			if err != nil {
				if c.log != nil {
					c.log.Debugf(
						"🧦 <yellow>Polling Next Server Packet Failed, Stream ID: <cyan>%d</cyan> | Packet: <cyan>%s</cyan> | Resolver: <cyan>%s</cyan> | Error: <cyan>%v</cyan></yellow>",
						streamID,
						Enums.PacketTypeName(packetType),
						connection.ResolverLabel,
						err,
					)
				}
				return VpnProto.Packet{}, err
			}
			if c.log != nil {
				c.log.Debugf(
					"🧦 <blue>Polled Follow-up Packet, Stream ID: <cyan>%d</cyan> | Sent: <cyan>%s</cyan> | Got: <cyan>%s</cyan> | Resolver: <cyan>%s</cyan></blue>",
					streamID,
					Enums.PacketTypeName(packetType),
					Enums.PacketTypeName(packet.PacketType),
					connection.ResolverLabel,
				)
			}
			pollCount++
			if packet.PacketType == Enums.PACKET_PONG {
				remaining = time.Until(deadline)
				if remaining <= 0 {
					return VpnProto.Packet{}, fallbackErr
				}
				sleepFor := pongSleep
				if sleepFor > remaining {
					sleepFor = remaining
				}
				if sleepFor > 0 {
					time.Sleep(sleepFor)
				}
				pongSleep *= 2
				if pongSleep > streamControlPongSleepMax {
					pongSleep = streamControlPongSleepMax
				}
			}
		}
	}

	return VpnProto.Packet{}, fallbackErr
}

func (c *Client) buildStreamQuery(domain string, packetType uint8, streamID uint16, sequenceNum uint16, fragmentID uint8, totalFragments uint8, payload []byte) ([]byte, error) {
	return c.buildTunnelTXTQuery(domain, VpnProto.BuildOptions{
		SessionID:       c.sessionID,
		PacketType:      packetType,
		SessionCookie:   c.sessionCookie,
		StreamID:        streamID,
		SequenceNum:     sequenceNum,
		FragmentID:      fragmentID,
		TotalFragments:  totalFragments,
		CompressionType: c.uploadCompression,
		Payload:         payload,
	})
}

func isSOCKS5ErrorPacket(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_SOCKS5_CONNECT_FAIL,
		Enums.PACKET_SOCKS5_RULESET_DENIED,
		Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE,
		Enums.PACKET_SOCKS5_HOST_UNREACHABLE,
		Enums.PACKET_SOCKS5_CONNECTION_REFUSED,
		Enums.PACKET_SOCKS5_TTL_EXPIRED,
		Enums.PACKET_SOCKS5_COMMAND_UNSUPPORTED,
		Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
		Enums.PACKET_SOCKS5_AUTH_FAILED,
		Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE:
		return true
	default:
		return false
	}
}

func shouldRetryStreamControlPacket(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_STREAM_SYN,
		Enums.PACKET_SOCKS5_SYN,
		Enums.PACKET_STREAM_FIN,
		Enums.PACKET_STREAM_RST:
		return true
	default:
		return false
	}
}

func findExpectedPackedStreamResponse(sentType uint8, streamID uint16, sequenceNum uint16, packet VpnProto.Packet) (VpnProto.Packet, bool) {
	if packet.PacketType != Enums.PACKET_PACKED_CONTROL_BLOCKS || len(packet.Payload) < arq.PackedControlBlockSize {
		return VpnProto.Packet{}, false
	}

	var matched VpnProto.Packet
	found := false
	arq.ForEachPackedControlBlock(packet.Payload, func(packetType uint8, blockStreamID uint16, blockSequenceNum uint16, fragmentID uint8, totalFragments uint8) bool {
		candidate := VpnProto.Packet{
			PacketType:     packetType,
			StreamID:       blockStreamID,
			HasStreamID:    blockStreamID != 0,
			SequenceNum:    blockSequenceNum,
			HasSequenceNum: blockSequenceNum != 0,
			FragmentID:     fragmentID,
			TotalFragments: totalFragments,
		}
		if matchesExpectedStreamResponse(sentType, streamID, sequenceNum, candidate) {
			matched = candidate
			found = true
			return false
		}
		return true
	})
	return matched, found
}
