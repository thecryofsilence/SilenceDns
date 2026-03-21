// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"time"

	"masterdnsvpn-go/internal/arq"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

var ErrTunnelDNSDispatchFailed = errors.New("dns tunnel dispatch failed")
var ErrTunnelDNSFragmentTooLarge = errors.New("dns tunnel payload exceeds fragment limit")

func (c *Client) sendScheduledPacket(packet arq.QueuedPacket) (VpnProto.Packet, error) {
	if c == nil {
		return VpnProto.Packet{}, ErrTunnelDNSDispatchFailed
	}

	timeout := normalizeTimeout(time.Duration(c.cfg.LocalDNSPendingTimeoutSec*float64(time.Second)), defaultRuntimeTimeout)

	// Session Guard: Do not send session-indexed packets if session is not ready
	if !c.SessionReady() {
		return VpnProto.Packet{}, ErrTunnelDNSDispatchFailed
	}

	switch packet.PacketType {
	case Enums.PACKET_DNS_QUERY_REQ, Enums.PACKET_DNS_QUERY_RES_ACK:
		return c.sendMainQueuedPacket(packet, nil, timeout)
	case Enums.PACKET_PING:
		return c.sendSessionControlPacket(packet.PacketType, packet.Payload, nil, timeout)
	default:
		if packet.StreamID == 0 {
			return VpnProto.Packet{}, ErrTunnelDNSDispatchFailed
		}
		return c.sendStreamPacket(packet, nil, timeout)
	}
}

func (c *Client) sendQueuedRuntimePacket(packet arq.QueuedPacket) error {
	if c == nil || !c.SessionReady() {
		return ErrTunnelDNSDispatchFailed
	}

	var (
		connections []Connection
		err         error
	)
	if packet.StreamID == 0 {
		connections, err = c.selectTargetConnectionsForPacket(packet.PacketType, 0)
	} else {
		connections, err = c.selectTargetConnectionsForPacket(packet.PacketType, packet.StreamID)
	}
	if err != nil {
		return err
	}

	deadline := time.Now().Add(defaultRuntimeTimeout)
	return sendRuntimeQueuedPacketParallel(connections, ErrTunnelDNSDispatchFailed, func(connection Connection) error {
		return c.sendQueuedRuntimePacketWithConnection(connection, packet, deadline)
	})
}

func sendRuntimeQueuedPacketParallel(connections []Connection, fallbackErr error, fn func(Connection) error) error {
	switch len(connections) {
	case 0:
		return fallbackErr
	case 1:
		return fn(connections[0])
	}

	lastErr := fallbackErr
	successCount := 0
	for _, connection := range connections {
		if err := fn(connection); err != nil {
			lastErr = err
			continue
		}
		successCount++
	}
	if successCount > 0 {
		return nil
	}
	return lastErr
}

func (c *Client) sendQueuedRuntimePacketWithConnection(connection Connection, packet arq.QueuedPacket, deadline time.Time) error {
	if c == nil {
		return ErrTunnelDNSDispatchFailed
	}
	if packet.StreamID == 0 {
		return c.sendQueuedMainPacketOneWay(connection, packet, deadline)
	}
	return c.sendQueuedStreamPacketOneWay(connection, packet, deadline)
}

func (c *Client) sendQueuedMainPacketOneWay(connection Connection, packet arq.QueuedPacket, deadline time.Time) error {
	var (
		query []byte
		err   error
	)
	switch packet.PacketType {
	case Enums.PACKET_PING:
		query, err = c.buildSessionControlQuery(connection.Domain, packet.PacketType, packet.Payload)
	default:
		query, err = c.buildTunnelTXTQuery(connection.Domain, VpnProto.BuildOptions{
			SessionID:       c.sessionID,
			PacketType:      packet.PacketType,
			SessionCookie:   c.sessionCookie,
			StreamID:        0,
			SequenceNum:     packet.SequenceNum,
			FragmentID:      packet.FragmentID,
			TotalFragments:  normalizeMainTotalFragments(packet.TotalFragments),
			CompressionType: packet.CompressionType,
			Payload:         packet.Payload,
		})
	}
	if err != nil {
		return err
	}
	return c.sendRuntimeQuery(connection, query, deadline)
}

func (c *Client) sendQueuedStreamPacketOneWay(connection Connection, packet arq.QueuedPacket, deadline time.Time) error {
	fragments, err := c.fragmentMainStreamPayload(connection.Domain, packet.PacketType, packet.Payload)
	if err != nil {
		return err
	}
	totalFragments := uint8(len(fragments))
	if totalFragments == 0 {
		totalFragments = 1
	}
	for fragmentID, fragmentPayload := range fragments {
		query, buildErr := c.buildStreamQuery(
			connection.Domain,
			packet.PacketType,
			packet.StreamID,
			packet.SequenceNum,
			uint8(fragmentID),
			totalFragments,
			fragmentPayload,
		)
		if buildErr != nil {
			return buildErr
		}
		if err := c.sendRuntimeQuery(connection, query, deadline); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) sendRuntimeQuery(connection Connection, query []byte, deadline time.Time) error {
	if c == nil {
		return ErrTunnelDNSDispatchFailed
	}
	c.noteResolverSend(connection.Key)
	if c.exchangeQueryFn != nil {
		timeout := time.Until(deadline)
		if timeout <= 0 {
			timeout = defaultRuntimeTimeout
		}
		response, err := c.exchangeQueryFn(connection, query, timeout)
		if err != nil {
			return err
		}
		if len(response) == 0 {
			return nil
		}
		packet, err := c.parseValidatedServerPacket(response, ErrTunnelDNSDispatchFailed)
		if err != nil {
			return err
		}
		return c.handleAsyncServerPacket(packet, timeout)
	}
	if c.sendOneWayPacketFn != nil {
		if err := c.sendOneWayPacketFn(connection, query, deadline); err != nil {
			return err
		}
		return nil
	}
	c.sendFastOneWayUDP(connection.ResolverLabel, query, deadline)
	return nil
}

func (c *Client) sendStreamPacket(packet arq.QueuedPacket, connections []Connection, timeout time.Duration) (VpnProto.Packet, error) {
	if c == nil {
		return VpnProto.Packet{}, ErrStreamHandshakeFailed
	}
	timeout = normalizeTimeout(timeout, defaultRuntimeTimeout)
	var err error
	if len(connections) == 0 {
		connections, err = c.selectTargetConnectionsForPacket(packet.PacketType, packet.StreamID)
	} else {
		connections, err = c.runtimeConnections(connections)
	}

	if err != nil {
		return VpnProto.Packet{}, err
	}

	return tryConnectionsParallel(connections, ErrStreamHandshakeFailed, func(connection Connection) (VpnProto.Packet, error) {
		return c.sendStreamControlPacketWithConnection(
			connection,
			packet.PacketType,
			packet.StreamID,
			packet.SequenceNum,
			packet.Payload,
			timeout,
		)
	})
}

func (c *Client) sendMainQueuedPacket(packet arq.QueuedPacket, connections []Connection, timeout time.Duration) (VpnProto.Packet, error) {
	if c == nil {
		return VpnProto.Packet{}, ErrTunnelDNSDispatchFailed
	}
	timeout = normalizeTimeout(timeout, defaultRuntimeTimeout)
	var err error
	if len(connections) == 0 {
		connections, err = c.selectTargetConnectionsForPacket(packet.PacketType, 0)
	} else {
		connections, err = c.runtimeConnections(connections)
	}
	if err != nil {
		return VpnProto.Packet{}, err
	}
	return tryConnectionsParallel(connections, ErrTunnelDNSDispatchFailed, func(connection Connection) (VpnProto.Packet, error) {
		return c.sendMainQueuedPacketWithConnection(connection, packet, timeout)
	})
}

func (c *Client) sendMainQueuedPacketWithConnection(connection Connection, packet arq.QueuedPacket, timeout time.Duration) (VpnProto.Packet, error) {
	query, err := c.buildTunnelTXTQuery(connection.Domain, VpnProto.BuildOptions{
		SessionID:       c.sessionID,
		PacketType:      packet.PacketType,
		SessionCookie:   c.sessionCookie,
		StreamID:        0,
		SequenceNum:     packet.SequenceNum,
		FragmentID:      packet.FragmentID,
		TotalFragments:  normalizeMainTotalFragments(packet.TotalFragments),
		CompressionType: packet.CompressionType,
		Payload:         packet.Payload,
	})
	if err != nil {
		return VpnProto.Packet{}, err
	}

	return c.exchangeDNSOverConnection(connection, query, timeout)
}

func (c *Client) buildSessionControlQuery(domain string, packetType uint8, payload []byte) ([]byte, error) {
	return c.buildTunnelTXTQuery(domain, VpnProto.BuildOptions{
		SessionID:     c.sessionID,
		PacketType:    packetType,
		SessionCookie: c.sessionCookie,
		Payload:       payload,
	})
}

func (c *Client) fragmentMainStreamPayload(domain string, packetType uint8, payload []byte) ([][]byte, error) {
	if len(payload) == 0 {
		return [][]byte{{}}, nil
	}

	limit := c.maxMainStreamFragmentPayload(domain, packetType)
	if limit < 1 {
		return nil, ErrTunnelDNSDispatchFailed
	}
	if len(payload) <= limit {
		return [][]byte{payload}, nil
	}

	total := (len(payload) + limit - 1) / limit
	if total > 255 {
		return nil, ErrTunnelDNSFragmentTooLarge
	}

	fragments := make([][]byte, 0, total)
	for start := 0; start < len(payload); start += limit {
		end := start + limit
		if end > len(payload) {
			end = len(payload)
		}
		fragments = append(fragments, payload[start:end])
	}
	return fragments, nil
}

func (c *Client) fragmentQueuedMainPayload(packetType uint8, payload []byte) ([][]byte, error) {
	if c == nil {
		return nil, ErrTunnelDNSDispatchFailed
	}
	if len(payload) == 0 {
		return [][]byte{{}}, nil
	}

	limit := c.maxQueuedMainFragmentPayload(packetType)
	if limit < 1 {
		return nil, ErrTunnelDNSDispatchFailed
	}
	if len(payload) <= limit {
		return [][]byte{payload}, nil
	}

	total := (len(payload) + limit - 1) / limit
	if total > 255 {
		return nil, ErrTunnelDNSFragmentTooLarge
	}

	fragments := make([][]byte, 0, total)
	for start := 0; start < len(payload); start += limit {
		end := start + limit
		if end > len(payload) {
			end = len(payload)
		}
		fragments = append(fragments, payload[start:end])
	}
	return fragments, nil
}

func (c *Client) exchangeDNSOverConnection(connection Connection, packet []byte, timeout time.Duration) (VpnProto.Packet, error) {
	startedAt := c.now()
	c.noteResolverSend(connection.Key)

	if c != nil && c.exchangeQueryFn != nil {
		response, err := c.exchangeQueryFn(connection, packet, timeout)
		if err != nil {
			if isResolverTimeout(err) {
				c.noteResolverTimeout(connection.Key)
			}
			return VpnProto.Packet{}, err
		}
		c.noteResolverSuccess(connection.Key, c.now().Sub(startedAt))
		return c.parseValidatedServerPacket(response, ErrTunnelDNSDispatchFailed)
	}

	conn, err := c.getUDPConn(connection.ResolverLabel)
	if err != nil {
		return VpnProto.Packet{}, err
	}

	response, err := c.exchangeUDPQueryWithConn(conn, packet, timeout)
	if err != nil {
		_ = conn.Close() // Don't return to pool on error
		if isResolverTimeout(err) {
			c.noteResolverTimeout(connection.Key)
		}
		return VpnProto.Packet{}, err
	}

	c.putUDPConn(connection.ResolverLabel, conn)
	c.noteResolverSuccess(connection.Key, c.now().Sub(startedAt))
	packetResponse, err := c.parseValidatedServerPacket(response, ErrTunnelDNSDispatchFailed)
	if len(packetResponse.Payload) != 0 {
		packetResponse.Payload = append([]byte(nil), packetResponse.Payload...)
	}
	c.putRuntimeUDPBuffer(response)
	return packetResponse, err
}

func (c *Client) getUDPConn(resolverLabel string) (*net.UDPConn, error) {
	c.resolverConnsMu.Lock()
	pool, ok := c.resolverConns[resolverLabel]
	if !ok {
		pool = make(chan *net.UDPConn, 32)
		c.resolverConns[resolverLabel] = pool
	}
	c.resolverConnsMu.Unlock()

	select {
	case conn := <-pool:
		return conn, nil
	default:
		return dialUDPResolver(resolverLabel)
	}
}

func (c *Client) putUDPConn(resolverLabel string, conn *net.UDPConn) {
	if conn == nil {
		return
	}
	c.resolverConnsMu.Lock()
	pool := c.resolverConns[resolverLabel]
	c.resolverConnsMu.Unlock()

	if pool == nil {
		_ = conn.Close()
		return
	}

	select {
	case pool <- conn:
	default:
		_ = conn.Close()
	}
}

func (c *Client) exchangeUDPQueryWithConn(conn *net.UDPConn, packet []byte, timeout time.Duration) ([]byte, error) {
	if len(packet) < 2 {
		return nil, errors.New("malformed dns query")
	}
	expectedID := packet[:2]

	// Drain any stale packets from the buffer (non-blocking)
	drainBuffer := c.getRuntimeUDPBuffer()
	for {
		if err := conn.SetReadDeadline(time.Now()); err != nil {
			break
		}
		if _, err := conn.Read(drainBuffer); err != nil {
			break
		}
	}
	c.putRuntimeUDPBuffer(drainBuffer)

	timeout = normalizeTimeout(timeout, time.Second)
	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, os.ErrDeadlineExceeded
		}

		buffer := c.getRuntimeUDPBuffer()
		n, err := conn.Read(buffer)
		if err != nil {
			c.putRuntimeUDPBuffer(buffer)
			return nil, err
		}

		if n >= 2 && buffer[0] == expectedID[0] && buffer[1] == expectedID[1] {
			return buffer[:n], nil
		}
		// Stale packet or from another request, continue reading until timeout
		c.putRuntimeUDPBuffer(buffer)
	}
}

func isResolverTimeout(err error) bool {
	if err == nil {
		return false
	}
	if os.IsTimeout(err) {
		return true
	}
	timeoutErr, ok := err.(net.Error)
	return ok && timeoutErr.Timeout()
}

func (c *Client) nextMainSequence() uint16 {
	if c == nil {
		return 1
	}
	c.mainSequence++
	if c.mainSequence == 0 {
		c.mainSequence = 1
	}
	return c.mainSequence
}

func normalizeMainTotalFragments(total uint8) uint8 {
	if total == 0 {
		return 1
	}
	return total
}

func (c *Client) maxQueuedMainFragmentPayload(packetType uint8) int {
	if c == nil {
		return 0
	}
	best := 0
	for _, domain := range c.cfg.Domains {
		limit := c.maxMainStreamFragmentPayload(domain, packetType)
		if limit <= 0 {
			continue
		}
		if best == 0 || limit < best {
			best = limit
		}
	}
	return best
}

func (c *Client) maxMainStreamFragmentPayload(domain string, packetType uint8) int {
	if c == nil {
		return 0
	}

	type fragmentCacheKey struct {
		domain     string
		packetType uint8
	}

	key := fragmentCacheKey{domain: domain, packetType: packetType}
	if cached, ok := c.fragmentLimits.Load(key); ok {
		return cached.(int)
	}

	high := c.SafeUploadMTU()
	if high <= 0 {
		high = EDnsSafeUDPSize
	}
	best := 0
	low := 1
	for low <= high {
		mid := (low + high) / 2
		if c.canBuildMainStreamPayload(domain, packetType, mid) {
			best = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}

	c.fragmentLimits.Store(key, best)
	return best
}

func (c *Client) canBuildMainStreamPayload(domain string, packetType uint8, payloadLen int) bool {
	if payloadLen < 0 {
		return false
	}
	payload := make([]byte, payloadLen)
	_, err := c.buildStreamQuery(domain, packetType, 0, 1, 0, 1, payload)
	return err == nil
}

func shouldCacheTunnelDNSResponse(response []byte) bool {
	if len(response) < 4 {
		return false
	}
	return binary.BigEndian.Uint16(response[2:4])&0x000F != Enums.DNSR_CODE_SERVER_FAILURE
}

func (c *Client) buildTunnelTXTQuery(domain string, options VpnProto.BuildOptions) ([]byte, error) {
	encoded, err := VpnProto.BuildEncodedAuto(options, c.codec, c.cfg.CompressionMinSize)
	if err != nil {
		return nil, err
	}
	return buildTunnelTXTQuestion(domain, encoded)
}

type udpQueryTransport struct {
	conn   *net.UDPConn
	buffer []byte
}

func runtimeUDPReadBufferSize() int {
	return 65535
}

func (c *Client) getRuntimeUDPBuffer() []byte {
	if c == nil {
		return make([]byte, runtimeUDPReadBufferSize())
	}
	buf, _ := c.udpBufferPool.Get().([]byte)
	if cap(buf) < runtimeUDPReadBufferSize() {
		return make([]byte, runtimeUDPReadBufferSize())
	}
	return buf[:runtimeUDPReadBufferSize()]
}

func (c *Client) putRuntimeUDPBuffer(buf []byte) {
	if c == nil || buf == nil {
		return
	}
	if cap(buf) < runtimeUDPReadBufferSize() {
		return
	}
	c.udpBufferPool.Put(buf[:runtimeUDPReadBufferSize()])
}

func dialUDPResolver(resolverLabel string) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", resolverLabel)
	if err != nil {
		return nil, err
	}
	return net.DialUDP("udp", nil, addr)
}

func newUDPQueryTransport(resolverLabel string) (*udpQueryTransport, error) {
	conn, err := dialUDPResolver(resolverLabel)
	if err != nil {
		return nil, err
	}
	return &udpQueryTransport{
		conn:   conn,
		buffer: make([]byte, runtimeUDPReadBufferSize()),
	}, nil
}

func (c *Client) sendFastOneWayUDP(resolverLabel string, packet []byte, deadline time.Time) {
	conn, err := dialUDPResolver(resolverLabel)
	if err != nil {
		return
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(deadline)
	_, _ = conn.Write(packet)
}

func exchangeUDPQuery(transport *udpQueryTransport, packet []byte, timeout time.Duration) ([]byte, error) {
	if transport == nil || transport.conn == nil {
		return nil, net.ErrClosed
	}
	if len(packet) < 2 {
		return nil, errors.New("malformed dns query")
	}
	expectedID := packet[:2]

	// Drain any stale packets from the buffer (non-blocking) before sending
	drainBuffer := make([]byte, 2048)
	for {
		if err := transport.conn.SetReadDeadline(time.Now()); err != nil {
			break
		}
		if _, err := transport.conn.Read(drainBuffer); err != nil {
			break
		}
	}

	timeout = normalizeTimeout(timeout, time.Second)
	deadline := time.Now().Add(timeout)
	if err := transport.conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	if _, err := transport.conn.Write(packet); err != nil {
		return nil, err
	}

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, os.ErrDeadlineExceeded
		}

		n, err := transport.conn.Read(transport.buffer)
		if err != nil {
			return nil, err
		}

		if n >= 2 && transport.buffer[0] == expectedID[0] && transport.buffer[1] == expectedID[1] {
			return append([]byte(nil), transport.buffer[:n]...), nil
		}
		// Stale packet or from another request, continue reading until timeout
	}
}

func (c *Client) sendSessionControlPacket(packetType uint8, payload []byte, connections []Connection, timeout time.Duration) (VpnProto.Packet, error) {
	if c == nil {
		return VpnProto.Packet{}, ErrTunnelDNSDispatchFailed
	}
	timeout = normalizeTimeout(timeout, defaultRuntimeTimeout)
	var err error
	if len(connections) == 0 {
		connections, err = c.selectTargetConnectionsForPacket(packetType, 0)
	} else {
		connections, err = c.runtimeConnections(connections)
	}
	if err != nil {
		return VpnProto.Packet{}, err
	}
	return tryConnectionsParallel(connections, ErrTunnelDNSDispatchFailed, func(connection Connection) (VpnProto.Packet, error) {
		return c.sendSessionControlPacketWithConnection(connection, packetType, payload, timeout)
	})
}

func (c *Client) sendSessionControlPacketWithConnection(connection Connection, packetType uint8, payload []byte, timeout time.Duration) (VpnProto.Packet, error) {
	query, err := c.buildSessionControlQuery(connection.Domain, packetType, payload)
	if err != nil {
		return VpnProto.Packet{}, err
	}

	return c.exchangeDNSOverConnection(connection, query, timeout)
}

func (c *Client) parseValidatedServerPacket(response []byte, fallbackErr error) (VpnProto.Packet, error) {
	packet, err := DnsParser.ExtractVPNResponse(response, c.responseMode == mtuProbeBase64Reply)
	if err != nil || !c.validateServerPacket(packet) {
		return VpnProto.Packet{}, fallbackErr
	}
	return packet, nil
}
