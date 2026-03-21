// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	SocksProto "masterdnsvpn-go/internal/socksproto"
)

var errSOCKS5UnsupportedCommand = errors.New("unsupported socks5 command")
var errSOCKS5AuthFailed = errors.New("socks5 authentication failed")

type socks5HandshakeRequest struct {
	Command       byte
	TargetPayload []byte
}

func (c *Client) RunLocalSOCKS5Listener(ctx context.Context) error {
	if c == nil {
		return nil
	}
	return c.runLocalTCPAcceptLoop(
		ctx,
		net.JoinHostPort(c.cfg.ListenIP, strconv.Itoa(c.cfg.ListenPort)),
		func() {
			c.log.Infof(
				"\U0001F9E6 <green>Local SOCKS5 Listener Ready Addr: <cyan>%s:%d</cyan></green>",
				c.cfg.ListenIP,
				c.cfg.ListenPort,
			)
		},
		c.handleLocalSOCKS5Conn,
	)
}

func (c *Client) handleLocalSOCKS5Conn(conn net.Conn) {
	withLocalConnLifecycle(conn, func(recovered any) {
		if c.log != nil {
			c.log.Errorf(
				"\U0001F4A5 <red>SOCKS5 Handler Panic Recovered: <yellow>%v</yellow></red>",
				recovered,
			)
		}
	}, func() bool {
		timeout := localHandshakeTimeout(time.Duration(c.cfg.LocalSOCKS5HandshakeSec*float64(time.Second)), 10*time.Second)
		_ = conn.SetDeadline(time.Now().Add(timeout))
		clientIP := peerAddrString(conn)

		request, err := c.performSOCKS5Handshake(conn)
		if err != nil {
			if c.log != nil {
				switch {
				case errors.Is(err, errSOCKS5AuthFailed):
					c.log.Warnf(
						"🔒 <yellow>SOCKS5 Auth Failed, Client: <cyan>%s</cyan></yellow>",
						clientIP,
					)
				default:
					c.log.Debugf(
						"🧦 <yellow>SOCKS5 Handshake Failed, Client: <cyan>%s</cyan> | Error: <cyan>%v</cyan></yellow>",
						clientIP,
						err,
					)
				}
			}
			if !errors.Is(err, errSOCKS5AuthFailed) {
				_ = writeSOCKS5Failure(conn, 0x07)
			}
			return false
		}
		targetText := formatSOCKS5TargetPayload(request.TargetPayload)

		switch request.Command {
		case 0x01:
			if c.log != nil {
				c.log.Infof(
					"🧦 <green>SOCKS5 CONNECT Requested, Client: <cyan>%s</cyan> | Target: <cyan>%s</cyan></green>",
					clientIP,
					targetText,
				)
			}
			streamID, openErr := c.OpenSOCKS5Stream(request.TargetPayload, timeout)
			if openErr != nil {
				if c.log != nil {
					c.log.Debugf(
						"🧦 <yellow>SOCKS5 CONNECT Failed, Client: <cyan>%s</cyan> | Target: <cyan>%s</cyan> | Error: <cyan>%v</cyan></yellow>",
						clientIP,
						targetText,
						openErr,
					)
				}
				_ = writeSOCKS5Failure(conn, mapSOCKS5FailureReply(openErr))
				return false
			}
			if _, writeErr := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); writeErr != nil {
				if c.log != nil {
					c.log.Debugf(
						"🧦 <yellow>SOCKS5 Reply Write Failed, Stream: <cyan>%d</cyan> | Client: <cyan>%s</cyan> | Error: <cyan>%v</cyan></yellow>",
						streamID,
						clientIP,
						writeErr,
					)
				}
				return false
			}
			if c.log != nil {
				c.log.Infof(
					"🧦 <green>SOCKS5 Stream Ready, Stream ID: <cyan>%d</cyan> | Client: <cyan>%s</cyan> | Target: <cyan>%s</cyan></green>",
					streamID,
					clientIP,
					targetText,
				)
			}
			if c.log != nil {
				c.log.Debugf(
					"🧦 <blue>SOCKS5 Stream Attached, Stream ID: <cyan>%d</cyan> | Target: <cyan>%s</cyan></blue>",
					streamID,
					targetText,
				)
			}
			attachLocalStreamConn(c, streamID, conn, timeout)
			return true
		case 0x03:
			if c.log != nil {
				c.log.Debugf(
					"🧦 <yellow>SOCKS5 UDP Associate Requested, Client: <cyan>%s</cyan></yellow>",
					clientIP,
				)
			}
			_ = conn.SetDeadline(time.Time{})
			if err := c.runLocalSOCKS5UDPAssociate(conn); err != nil && c.log != nil {
				c.log.Debugf(
					"\U0001F9E6 <yellow>SOCKS5 UDP Associate Closed: <cyan>%v</cyan></yellow>",
					err,
				)
			}
			return false
		default:
			_ = writeSOCKS5Failure(conn, 0x07)
			return false
		}
	})
}

func (c *Client) performSOCKS5Handshake(conn net.Conn) (socks5HandshakeRequest, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return socks5HandshakeRequest{}, err
	}
	if header[0] != 0x05 || header[1] == 0 {
		return socks5HandshakeRequest{}, errSOCKS5UnsupportedCommand
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return socks5HandshakeRequest{}, err
	}
	supportsNoAuth := false
	supportsUserPass := false
	for _, method := range methods {
		switch method {
		case 0x00:
			supportsNoAuth = true
		case 0x02:
			supportsUserPass = true
		}
	}

	if c != nil && c.cfg.SOCKS5Auth {
		if !supportsUserPass {
			_, _ = conn.Write([]byte{0x05, 0xFF})
			return socks5HandshakeRequest{}, errSOCKS5UnsupportedCommand
		}
		if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
			return socks5HandshakeRequest{}, err
		}
		if err := c.handleSOCKS5UserPassAuth(conn); err != nil {
			return socks5HandshakeRequest{}, err
		}
	} else if !supportsNoAuth {
		_, _ = conn.Write([]byte{0x05, 0xFF})
		return socks5HandshakeRequest{}, errSOCKS5UnsupportedCommand
	} else {
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			return socks5HandshakeRequest{}, err
		}
	}

	requestHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, requestHeader); err != nil {
		return socks5HandshakeRequest{}, err
	}
	if requestHeader[0] != 0x05 || requestHeader[2] != 0x00 {
		return socks5HandshakeRequest{}, errSOCKS5UnsupportedCommand
	}
	if requestHeader[1] != 0x01 && requestHeader[1] != 0x03 {
		return socks5HandshakeRequest{}, errSOCKS5UnsupportedCommand
	}

	payload, err := readSOCKS5TargetPayload(conn, requestHeader[3])
	if err != nil {
		return socks5HandshakeRequest{}, err
	}
	return socks5HandshakeRequest{
		Command:       requestHeader[1],
		TargetPayload: payload,
	}, nil
}

func (c *Client) handleSOCKS5UserPassAuth(conn net.Conn) error {
	if c == nil || conn == nil {
		return errSOCKS5UnsupportedCommand
	}

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != 0x01 || header[1] == 0 {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return errSOCKS5AuthFailed
	}

	user := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, user); err != nil {
		return err
	}

	passLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLen); err != nil {
		return err
	}
	if passLen[0] == 0 {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return errSOCKS5AuthFailed
	}

	pass := make([]byte, int(passLen[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}

	if string(user) != c.cfg.SOCKS5User || string(pass) != c.cfg.SOCKS5Pass {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return errSOCKS5AuthFailed
	}

	_, err := conn.Write([]byte{0x01, 0x00})
	return err
}

func readSOCKS5TargetPayload(conn net.Conn, atyp byte) ([]byte, error) {
	switch atyp {
	case 0x01:
		payload := make([]byte, 1+4+2)
		payload[0] = atyp
		if _, err := io.ReadFull(conn, payload[1:]); err != nil {
			return nil, err
		}
		return payload, nil
	case 0x03:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return nil, err
		}
		if length[0] == 0 {
			return nil, SocksProto.ErrInvalidDomainLength
		}
		payload := make([]byte, 1+1+int(length[0])+2)
		payload[0] = atyp
		payload[1] = length[0]
		if _, err := io.ReadFull(conn, payload[2:]); err != nil {
			return nil, err
		}
		return payload, nil
	case 0x04:
		payload := make([]byte, 1+16+2)
		payload[0] = atyp
		if _, err := io.ReadFull(conn, payload[1:]); err != nil {
			return nil, err
		}
		return payload, nil
	default:
		return nil, SocksProto.ErrUnsupportedAddressType
	}
}

func formatSOCKS5TargetPayload(payload []byte) string {
	if len(payload) < 1 {
		return "<invalid>"
	}
	switch payload[0] {
	case 0x01:
		if len(payload) != 1+4+2 {
			return "<invalid-ipv4>"
		}
		host := net.IP(payload[1:5]).String()
		port := int(payload[5])<<8 | int(payload[6])
		return net.JoinHostPort(host, strconv.Itoa(port))
	case 0x03:
		if len(payload) < 1+1+2 {
			return "<invalid-domain>"
		}
		dlen := int(payload[1])
		if len(payload) != 1+1+dlen+2 {
			return "<invalid-domain>"
		}
		host := string(payload[2 : 2+dlen])
		portIdx := 2 + dlen
		port := int(payload[portIdx])<<8 | int(payload[portIdx+1])
		return net.JoinHostPort(host, strconv.Itoa(port))
	case 0x04:
		if len(payload) != 1+16+2 {
			return "<invalid-ipv6>"
		}
		host := net.IP(payload[1:17]).String()
		port := int(payload[17])<<8 | int(payload[18])
		return net.JoinHostPort(host, strconv.Itoa(port))
	default:
		return fmt.Sprintf("<atyp:%d>", payload[0])
	}
}

func peerAddrString(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return "unknown"
	}
	return conn.RemoteAddr().String()
}

func writeSOCKS5Failure(conn net.Conn, rep byte) error {
	_, err := conn.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

func mapSOCKS5FailureReply(err error) byte {
	if err == nil {
		return 0x01
	}
	switch {
	case errors.Is(err, errSOCKS5UnsupportedCommand):
		return 0x07
	case errors.Is(err, errSOCKS5AuthFailed):
		return 0x01
	case errors.Is(err, SocksProto.ErrUnsupportedAddressType):
		return 0x08
	default:
		name := strings.ToUpper(err.Error())
		switch name {
		case "PACKET_SOCKS5_CONNECTION_REFUSED":
			return 0x05
		case "PACKET_SOCKS5_NETWORK_UNREACHABLE":
			return 0x03
		case "PACKET_SOCKS5_HOST_UNREACHABLE":
			return 0x04
		case "PACKET_SOCKS5_TTL_EXPIRED":
			return 0x06
		default:
			switch {
			case strings.Contains(name, "PACKET_SOCKS5_CONNECTION_REFUSED"):
				return 0x05
			case strings.Contains(name, "PACKET_SOCKS5_NETWORK_UNREACHABLE"):
				return 0x03
			case strings.Contains(name, "PACKET_SOCKS5_HOST_UNREACHABLE"):
				return 0x04
			case strings.Contains(name, "PACKET_SOCKS5_TTL_EXPIRED"):
				return 0x06
			}
			return 0x01
		}
	}
}

func (c *Client) runLocalSOCKS5UDPAssociate(conn net.Conn) error {
	if c == nil || conn == nil {
		return errSOCKS5UnsupportedCommand
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP(c.cfg.ListenIP),
		Port: 0,
	})
	if err != nil {
		_ = writeSOCKS5Failure(conn, 0x01)
		return err
	}
	defer udpConn.Close()

	if err := writeSOCKS5UDPAssociateReply(conn, udpConn.LocalAddr().(*net.UDPAddr)); err != nil {
		return err
	}

	controlClosed := make(chan struct{})
	go func() {
		defer close(controlClosed)
		sink := make([]byte, 1)
		_, _ = conn.Read(sink)
	}()

	buffer := make([]byte, EDnsSafeUDPSize+256)
	var clientAddr *net.UDPAddr
	for {
		_ = udpConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, addr, readErr := udpConn.ReadFromUDP(buffer)
		if readErr != nil {
			if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
				select {
				case <-controlClosed:
					return nil
				default:
					continue
				}
			}
			return readErr
		}

		if clientAddr == nil {
			clientAddr = addr
		} else if !addr.IP.Equal(clientAddr.IP) || addr.Port != clientAddr.Port {
			continue
		}

		now := c.now()
		response := c.handleSOCKS5UDPDatagram(buffer[:n], now)
		if len(response) == 0 {
			continue
		}
		if _, err := udpConn.WriteToUDP(response, clientAddr); err != nil {
			return err
		}
	}
}

func (c *Client) handleSOCKS5UDPDatagram(packet []byte, now time.Time) []byte {
	if c == nil {
		return nil
	}
	datagram, err := SocksProto.ParseUDPDatagram(packet)
	if err != nil {
		return nil
	}
	if datagram.Target.Port != 53 {
		return nil
	}
	response := c.resolveDNSQueryPacket(datagram.Payload, now)
	if len(response) == 0 {
		return nil
	}
	return SocksProto.BuildUDPDatagram(datagram.Target, response)
}

func writeSOCKS5UDPAssociateReply(conn net.Conn, addr *net.UDPAddr) error {
	if conn == nil || addr == nil {
		return errSOCKS5UnsupportedCommand
	}
	ipv4 := addr.IP.To4()
	if ipv4 == nil {
		ipv4 = net.IPv4zero.To4()
	}
	reply := make([]byte, 10)
	reply[0] = 0x05
	reply[1] = 0x00
	reply[2] = 0x00
	reply[3] = 0x01
	copy(reply[4:8], ipv4)
	reply[8] = byte(addr.Port >> 8)
	reply[9] = byte(addr.Port)
	_, err := conn.Write(reply)
	return err
}
