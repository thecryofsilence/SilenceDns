// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"sync"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
)

type streamStateRecord struct {
	SessionID      uint8
	StreamID       uint16
	State          uint8
	CreatedAt      time.Time
	LastActivityAt time.Time
	LastSequence   uint16
}

type streamStateStore struct {
	mu       sync.Mutex
	sessions map[uint8]map[uint16]*streamStateRecord
}

func newStreamStateStore() *streamStateStore {
	return &streamStateStore{
		sessions: make(map[uint8]map[uint16]*streamStateRecord, 32),
	}
}

func (s *streamStateStore) EnsureOpen(sessionID uint8, streamID uint16, now time.Time) (*streamStateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	streams := s.sessions[sessionID]
	if streams == nil {
		streams = make(map[uint16]*streamStateRecord, 8)
		s.sessions[sessionID] = streams
	}

	if record := streams[streamID]; record != nil {
		record.LastActivityAt = now
		return cloneStreamStateRecord(record), false
	}

	record := &streamStateRecord{
		SessionID:      sessionID,
		StreamID:       streamID,
		State:          Enums.STREAM_STATE_OPEN,
		CreatedAt:      now,
		LastActivityAt: now,
	}
	streams[streamID] = record
	return cloneStreamStateRecord(record), true
}

func (s *streamStateStore) Touch(sessionID uint8, streamID uint16, sequenceNum uint16, now time.Time) (*streamStateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		return nil, false
	}
	record.LastActivityAt = now
	record.LastSequence = sequenceNum
	return cloneStreamStateRecord(record), true
}

func (s *streamStateStore) MarkRemoteFin(sessionID uint8, streamID uint16, sequenceNum uint16, now time.Time) (*streamStateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		return nil, false
	}
	record.LastActivityAt = now
	record.LastSequence = sequenceNum
	switch record.State {
	case Enums.STREAM_STATE_HALF_CLOSED_LOCAL:
		record.State = Enums.STREAM_STATE_DRAINING
	case Enums.STREAM_STATE_OPEN:
		record.State = Enums.STREAM_STATE_HALF_CLOSED_REMOTE
	}
	return cloneStreamStateRecord(record), true
}

func (s *streamStateStore) MarkReset(sessionID uint8, streamID uint16, sequenceNum uint16, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	streams := s.sessions[sessionID]
	if streams == nil {
		return false
	}
	record := streams[streamID]
	if record == nil {
		return false
	}
	record.LastActivityAt = now
	record.LastSequence = sequenceNum
	record.State = Enums.STREAM_STATE_RESET
	delete(streams, streamID)
	if len(streams) == 0 {
		delete(s.sessions, sessionID)
	}
	return true
}

func (s *streamStateStore) Lookup(sessionID uint8, streamID uint16) (*streamStateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		return nil, false
	}
	return cloneStreamStateRecord(record), true
}

func (s *streamStateStore) RemoveSession(sessionID uint8) {
	s.mu.Lock()
	delete(s.sessions, sessionID)
	s.mu.Unlock()
}

func (s *streamStateStore) lookupLocked(sessionID uint8, streamID uint16) *streamStateRecord {
	streams := s.sessions[sessionID]
	if streams == nil {
		return nil
	}
	return streams[streamID]
}

func cloneStreamStateRecord(record *streamStateRecord) *streamStateRecord {
	if record == nil {
		return nil
	}
	cloned := *record
	return &cloned
}
