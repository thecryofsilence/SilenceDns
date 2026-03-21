// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
)

type upstreamSOCKS5Error struct {
	packetType uint8
	err        error
}

var (
	externalSOCKS5NoAuthGreeting = []byte{0x05, 0x01, 0x00}
	externalSOCKS5UserPassAuth   = []byte{0x05, 0x01, 0x02}
)

func (e *upstreamSOCKS5Error) Error() string {
	if e == nil || e.err == nil {
		return "upstream socks5 error"
	}
	return e.err.Error()
}

func (e *upstreamSOCKS5Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func (s *Server) dialSOCKSStreamTarget(host string, port uint16, targetPayload []byte) (net.Conn, error) {
	if s == nil {
		return nil, &upstreamSOCKS5Error{
			packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
			err:        errors.New("server unavailable"),
		}
	}

	if !s.useExternalSOCKS5 || len(targetPayload) == 0 {
		if s.log != nil {
			s.log.Debugf("🧦 <blue>Dialing Upstream TCP</blue> <magenta>|</magenta> <blue>Target</blue>: <cyan>%s:%d</cyan>", host, port)
		}
		return s.dialTCPTarget(net.JoinHostPort(host, strconv.Itoa(int(port))))
	}
	if s.log != nil {
		s.log.Debugf("🧦 <blue>Dialing External SOCKS5</blue> <magenta>|</magenta> <blue>Target</blue>: <cyan>%s:%d</cyan>", host, port)
	}
	return s.dialExternalSOCKS5Target(targetPayload)
}

func (s *Server) dialTCPTarget(address string) (net.Conn, error) {
	dialFn := s.dialStreamUpstreamFn
	if dialFn == nil {
		dialFn = func(network string, address string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout(network, address, timeout)
		}
	}
	timeout := s.socksConnectTimeout
	if timeout <= 0 {
		timeout = s.cfg.SOCKSConnectTimeout()
	}
	return dialFn("tcp", address, timeout)
}

func (s *Server) dialExternalSOCKS5Target(targetPayload []byte) (net.Conn, error) {
	conn, err := s.dialTCPTarget(s.externalSOCKS5Address)
	if err != nil {
		return nil, err
	}

	timeout := s.socksConnectTimeout
	if timeout <= 0 {
		timeout = s.cfg.SOCKSConnectTimeout()
	}
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	if err := writeAll(conn, s.externalSOCKS5Greeting()); err != nil {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE, err: err}
	}

	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE, err: err}
	}
	if greeting[0] != 0x05 {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{
			packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
			err:        errors.New("upstream proxy is not a valid SOCKS5 server"),
		}
	}
	if err := s.handleExternalSOCKS5Auth(conn, greeting[1]); err != nil {
		_ = conn.Close()
		return nil, err
	}

	request := make([]byte, 3+len(targetPayload))
	request[0] = 0x05
	request[1] = 0x01
	request[2] = 0x00
	copy(request[3:], targetPayload)
	if err := writeAll(conn, request); err != nil {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE, err: err}
	}

	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE, err: err}
	}
	if header[0] != 0x05 {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{
			packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
			err:        errors.New("invalid external SOCKS5 connect response"),
		}
	}
	if header[1] != 0x00 {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{
			packetType: socks5ReplyPacketType(header[1]),
			err:        fmt.Errorf("external SOCKS5 failed to connect to target: code %d", header[1]),
		}
	}
	if err := discardSOCKS5BoundAddress(conn, header[3]); err != nil {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE, err: err}
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func (s *Server) externalSOCKS5Greeting() []byte {
	if s != nil && s.externalSOCKS5Auth {
		return externalSOCKS5UserPassAuth
	}
	return externalSOCKS5NoAuthGreeting
}

func (s *Server) handleExternalSOCKS5Auth(conn net.Conn, method byte) error {
	if !s.externalSOCKS5Auth {
		if method == 0x00 {
			return nil
		}
		return &upstreamSOCKS5Error{
			packetType: Enums.PACKET_SOCKS5_AUTH_FAILED,
			err:        errors.New("external SOCKS5 requires unsupported authentication method"),
		}
	}

	if method != 0x02 {
		return &upstreamSOCKS5Error{
			packetType: Enums.PACKET_SOCKS5_AUTH_FAILED,
			err:        errors.New("external SOCKS5 authentication method mismatch"),
		}
	}

	request := make([]byte, 3+len(s.externalSOCKS5User)+len(s.externalSOCKS5Pass))
	request[0] = 0x01
	request[1] = byte(len(s.externalSOCKS5User))
	offset := 2
	offset += copy(request[offset:], s.externalSOCKS5User)
	request[offset] = byte(len(s.externalSOCKS5Pass))
	offset++
	copy(request[offset:], s.externalSOCKS5Pass)
	if err := writeAll(conn, request); err != nil {
		return &upstreamSOCKS5Error{packetType: Enums.PACKET_SOCKS5_AUTH_FAILED, err: err}
	}

	var response [2]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return &upstreamSOCKS5Error{packetType: Enums.PACKET_SOCKS5_AUTH_FAILED, err: err}
	}
	if response[1] != 0x00 {
		return &upstreamSOCKS5Error{
			packetType: Enums.PACKET_SOCKS5_AUTH_FAILED,
			err:        errors.New("external SOCKS5 authentication failed"),
		}
	}
	return nil
}

func discardSOCKS5BoundAddress(conn net.Conn, atyp byte) error {
	length := 0
	switch atyp {
	case 0x01:
		length = 4 + 2
	case 0x03:
		var dlen [1]byte
		if _, err := io.ReadFull(conn, dlen[:]); err != nil {
			return err
		}
		length = int(dlen[0]) + 2
	case 0x04:
		length = 16 + 2
	default:
		return errors.New("unsupported SOCKS5 bound address type")
	}
	if length == 0 {
		return nil
	}
	var buffer [257]byte
	_, err := io.ReadFull(conn, buffer[:length])
	return err
}

func socks5ReplyPacketType(reply byte) uint8 {
	switch reply {
	case 0x02:
		return Enums.PACKET_SOCKS5_RULESET_DENIED
	case 0x03:
		return Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE
	case 0x04:
		return Enums.PACKET_SOCKS5_HOST_UNREACHABLE
	case 0x05:
		return Enums.PACKET_SOCKS5_CONNECTION_REFUSED
	case 0x06:
		return Enums.PACKET_SOCKS5_TTL_EXPIRED
	case 0x07:
		return Enums.PACKET_SOCKS5_COMMAND_UNSUPPORTED
	case 0x08:
		return Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED
	default:
		return Enums.PACKET_SOCKS5_CONNECT_FAIL
	}
}

func writeAll(conn net.Conn, payload []byte) error {
	for len(payload) != 0 {
		n, err := conn.Write(payload)
		if err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
}
