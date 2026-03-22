// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"io"
	"sync"
	"time"

	"masterdnsvpn-go/internal/arq"
	"masterdnsvpn-go/internal/mlq"
)

// Stream_server encapsulates an ARQ instance and its transmit queue for a single stream.
type Stream_server struct {
	mu sync.RWMutex

	ID        uint16
	SessionID uint8
	ARQ       *arq.ARQ
	TXQueue   *mlq.MultiLevelQueue[*serverStreamTXPacket]

	Status       string
	CreatedAt    time.Time
	LastActivity time.Time
	CloseTime    time.Time

	UpstreamConn io.ReadWriteCloser
	TargetHost   string
	TargetPort   uint16
	Connected    bool

	// Tracking for deduplication (similar to Python's _track_stream_packet_once)
	// Key: packetType << 16 | sequenceNum
	// For data packets, we might also want to track by sequence if multiple types exist.
}

func NewStreamServer(streamID uint16, sessionID uint8, arqConfig arq.Config, localConn io.ReadWriteCloser, mtu int, logger arq.Logger) *Stream_server {
	s := &Stream_server{
		ID:           streamID,
		SessionID:    sessionID,
		TXQueue:      mlq.New[*serverStreamTXPacket](32),
		Status:       "CONNECTED",
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}

	s.ARQ = arq.NewARQ(streamID, sessionID, s, localConn, mtu, logger, arqConfig)
	s.ARQ.Start()
	return s
}

// PushTXPacket implements arq.PacketEnqueuer.
// It adds a packet to the stream's multi-level queue.
func (s *Stream_server) PushTXPacket(priority int, packetType uint8, sequenceNum uint16, fragmentID uint8, totalFragments uint8, compressionType uint8, payload []byte) bool {
	s.mu.Lock()
	s.LastActivity = time.Now()
	s.mu.Unlock()

	// Dedup and track logic would go here if needed.
	// For now, we use the MLQ's census for basic deduplication if we define a unique key.
	// Key: [Type(8)][Seq(16)][FragID(8)]
	key := getTrackingKey(packetType, sequenceNum, fragmentID)

	pkt := getTXPacketFromPool()
	pkt.PacketType = packetType
	pkt.SequenceNum = sequenceNum
	pkt.FragmentID = fragmentID
	pkt.TotalFragments = totalFragments
	pkt.CompressionType = compressionType
	pkt.Payload = payload
	pkt.CreatedAt = time.Now()

	ok := s.TXQueue.Push(priority, key, pkt)
	if !ok {
		// Packet already in queue or failed to push
		putTXPacketToPool(pkt)
		return false
	}

	// Notify session that this stream is active (handled by the caller or session management)
	return true
}

func (s *Stream_server) Close(reason string) {
	s.mu.Lock()
	if s.Status == "CLOSED" {
		s.mu.Unlock()
		return
	}
	s.Status = "CLOSED"
	s.CloseTime = time.Now()
	s.mu.Unlock()

	if s.ARQ != nil {
		s.ARQ.Close(reason, true)
	}
}

func (s *Stream_server) Abort(reason string) {
	s.mu.Lock()
	if s.Status == "CLOSED" {
		s.mu.Unlock()
		return
	}
	s.Status = "CLOSED"
	s.CloseTime = time.Now()
	s.mu.Unlock()

	if s.ARQ != nil {
		s.ARQ.Abort(reason, true)
	}
}
