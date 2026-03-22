// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"context"
	"sort"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func (c *Client) selectTargetConnections(packetType uint8, streamID uint16) []Connection {
	targetCount := c.cfg.PacketDuplicationCount
	if targetCount < 1 {
		targetCount = 1
	}

	// SYN packets often use higher duplication for reliability during handshake
	if packetType == Enums.PACKET_STREAM_SYN || packetType == Enums.PACKET_SOCKS5_SYN {
		if c.cfg.SetupPacketDuplicationCount > targetCount {
			targetCount = c.cfg.SetupPacketDuplicationCount
		}
	}

	// If duplication is disabled, just return the best connection (preferred if possible)
	if targetCount <= 1 {
		if streamID > 0 {
			c.streamsMu.RLock()
			s := c.active_streams[streamID]
			c.streamsMu.RUnlock()
			if s != nil && s.PreferredServerKey != "" {
				if idx, ok := c.connectionsByKey[s.PreferredServerKey]; ok {
					return []Connection{c.connections[idx]}
				}
			}
		}
		best, ok := c.balancer.GetBestConnection()
		if ok {
			return []Connection{best}
		}
		return nil
	}

	// For multiple packets, use unique connections from balancer
	return c.balancer.GetUniqueConnections(targetCount)
}

// asyncStreamDispatcher cycles through all active streams using a fair Round-Robin algorithm
// and transmits the highest priority packets to the TX workers, packing control blocks when possible.
func (c *Client) asyncStreamDispatcher(ctx context.Context) {
	c.log.Debugf("🚀 <cyan>Stream Dispatcher started</cyan>")
	defer c.asyncWG.Done()

	var rrCursor uint16 = 0

	for {
		// Wait for signal or timeout
		select {
		case <-ctx.Done():
			return
		case <-c.txSignal:
		case <-time.After(20 * time.Millisecond):
		}

		c.streamsMu.RLock()
		streamCount := len(c.active_streams)
		if streamCount == 0 {
			c.streamsMu.RUnlock()
			continue
		}

		ids := make([]uint16, 0, streamCount)
		for id := range c.active_streams {
			ids = append(ids, id)
		}
		c.streamsMu.RUnlock()

		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

		// Find the next stream to serve using fair Round-Robin across all active streams.
		var selected *Stream_client
		var item *clientStreamTXPacket
		var ok bool

		// Start search from rrCursor
		startIndex := -1
		for i, id := range ids {
			if id >= rrCursor {
				startIndex = i
				break
			}
		}
		if startIndex == -1 {
			startIndex = 0
		}

		for i := 0; i < len(ids); i++ {
			idx := (startIndex + i) % len(ids)
			id := ids[idx]

			c.streamsMu.RLock()
			s := c.active_streams[id]
			c.streamsMu.RUnlock()

			if s == nil || s.txQueue == nil {
				continue
			}

			// PopNextTXPacket returns the highest priority packet available for this stream.
			item, _, ok = s.PopNextTXPacket()
			if ok && item != nil {
				selected = s
				rrCursor = id + 1
				break
			}
		}

		if selected == nil || item == nil {
			continue
		}

		var finalPacket asyncPacket
		wasPacked := false
		maxBlocks := c.maxPackedBlocks
		if maxBlocks < 1 {
			maxBlocks = 1
		}

		if VpnProto.IsPackableControlPacket(item.PacketType, len(item.Payload)) && maxBlocks > 1 {
			payload := make([]byte, 0, maxBlocks*VpnProto.PackedControlBlockSize)
			payload = VpnProto.AppendPackedControlBlock(payload, item.PacketType, selected.StreamID, item.SequenceNum, item.FragmentID, item.TotalFragments)
			blocks := 1

			// Pop more from current stream if possible (Any priority)
			for blocks < maxBlocks {
				popped, poppedOk := selected.txQueue.PopAnyIf(func(p *clientStreamTXPacket) bool {
					return VpnProto.IsPackableControlPacket(p.PacketType, len(p.Payload))
				}, nil)
				if !poppedOk {
					break
				}
				payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, selected.StreamID, popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
				blocks++
				selected.ReleaseTXPacket(popped)
			}

			// Pop from other streams to fill block if space remains (Any priority)
			if blocks < maxBlocks {
				for _, sid := range ids {
					if blocks >= maxBlocks {
						break
					}
					if sid == selected.StreamID {
						continue
					}

					c.streamsMu.RLock()
					otherStream := c.active_streams[sid]
					c.streamsMu.RUnlock()

					if otherStream == nil || otherStream.txQueue == nil {
						continue
					}
					for blocks < maxBlocks {
						popped, poppedOk := otherStream.txQueue.PopAnyIf(func(p *clientStreamTXPacket) bool {
							return VpnProto.IsPackableControlPacket(p.PacketType, len(p.Payload))
						}, nil)
						if !poppedOk {
							break
						}
						payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, sid, popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
						blocks++
						otherStream.ReleaseTXPacket(popped)
					}
				}
			}

			if blocks > 1 {
				// Send as packed controls
				finalPacket = asyncPacket{
					packetType: Enums.PACKET_PACKED_CONTROL_BLOCKS,
					payload:    payload,
				}
				selected.ReleaseTXPacket(item)
				wasPacked = true
			} else {
				// Fallback natively if only 1 block found
				finalPacket = asyncPacket{
					packetType: item.PacketType,
					payload:    item.Payload,
				}
			}
		} else {
			finalPacket = asyncPacket{
				packetType: item.PacketType,
				payload:    item.Payload,
			}
		}

		// Notify Ping Manager of outbound activity
		c.pingManager.NotifyPacket(finalPacket.packetType, false)

		// Packet Duplication Logic
		conns := c.selectTargetConnections(finalPacket.packetType, selected.StreamID)
		if len(conns) == 0 {
			if !wasPacked {
				selected.ReleaseTXPacket(item)
			}
			continue
		}

		for _, conn := range conns {
			// Choose domain for this connection
			domain := conn.Domain
			if domain == "" {
				domain = c.cfg.Domains[0]
			}

			// Build THE final wrapped DNS packet
			opts := VpnProto.BuildOptions{
				SessionID:     c.sessionID,
				PacketType:    finalPacket.packetType,
				SessionCookie: c.sessionCookie,
			}

			if !wasPacked {
				opts.StreamID = selected.StreamID
				opts.SequenceNum = item.SequenceNum
				opts.FragmentID = item.FragmentID
				opts.TotalFragments = item.TotalFragments
				opts.Payload = item.Payload
			} else {
				opts.Payload = finalPacket.payload
			}

			encoded, err := VpnProto.BuildEncodedAuto(opts, c.codec, c.cfg.CompressionMinSize)
			if err != nil {
				c.log.Errorf("Failed to encode packet: %v", err)
				continue
			}

			dnsPacket, err := buildTunnelTXTQuestion(domain, encoded)
			if err != nil {
				c.log.Errorf("Failed to build DNS question: %v", err)
				continue
			}

			pkt := finalPacket
			pkt.conn = conn
			pkt.payload = dnsPacket

			// Send to TX channel
			c.log.Debugf("📤 <green>Dispatching packet (Type: %d) to %s:%d</green>", pkt.packetType, conn.Resolver, conn.ResolverPort)
			select {
			case c.txChannel <- pkt:
			default:
			}
		}

		if !wasPacked {
			selected.ReleaseTXPacket(item)
		}

		// Loop quickly if there's more potential work
		select {
		case c.txSignal <- struct{}{}:
		default:
		}
	}
}
