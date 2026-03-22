package arq

import (
	"testing"

	Enums "masterdnsvpn-go/internal/enums"
)

func TestControlAckPairsCoversAllAckedControlPackets(t *testing.T) {
	expectedPairs := map[uint8]uint8{
		Enums.PACKET_DNS_QUERY_REQ:                   Enums.PACKET_DNS_QUERY_REQ_ACK,
		Enums.PACKET_DNS_QUERY_RES:                   Enums.PACKET_DNS_QUERY_RES_ACK,
		Enums.PACKET_STREAM_SYN:                      Enums.PACKET_STREAM_SYN_ACK,
		Enums.PACKET_STREAM_FIN:                      Enums.PACKET_STREAM_FIN_ACK,
		Enums.PACKET_STREAM_RST:                      Enums.PACKET_STREAM_RST_ACK,
		Enums.PACKET_SOCKS5_SYN:                      Enums.PACKET_SOCKS5_SYN_ACK,
		Enums.PACKET_SOCKS5_CONNECT_FAIL:             Enums.PACKET_SOCKS5_CONNECT_FAIL_ACK,
		Enums.PACKET_SOCKS5_RULESET_DENIED:           Enums.PACKET_SOCKS5_RULESET_DENIED_ACK,
		Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE:      Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK,
		Enums.PACKET_SOCKS5_HOST_UNREACHABLE:         Enums.PACKET_SOCKS5_HOST_UNREACHABLE_ACK,
		Enums.PACKET_SOCKS5_CONNECTION_REFUSED:       Enums.PACKET_SOCKS5_CONNECTION_REFUSED_ACK,
		Enums.PACKET_SOCKS5_TTL_EXPIRED:              Enums.PACKET_SOCKS5_TTL_EXPIRED_ACK,
		Enums.PACKET_SOCKS5_COMMAND_UNSUPPORTED:      Enums.PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK,
		Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED: Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
		Enums.PACKET_SOCKS5_AUTH_FAILED:              Enums.PACKET_SOCKS5_AUTH_FAILED_ACK,
		Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE:     Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK,
		Enums.PACKET_SOCKS5_CONNECTED:                Enums.PACKET_SOCKS5_CONNECTED_ACK,
	}

	if len(ControlAckPairs) != len(expectedPairs) {
		t.Fatalf("unexpected control ack pair count: got %d want %d", len(ControlAckPairs), len(expectedPairs))
	}

	for packetType, ackType := range expectedPairs {
		got, ok := ControlAckPairs[packetType]
		if !ok {
			t.Fatalf("missing ack pair for packet type 0x%02X", packetType)
		}
		if got != ackType {
			t.Fatalf("unexpected ack pair for packet type 0x%02X: got 0x%02X want 0x%02X", packetType, got, ackType)
		}
	}
}
