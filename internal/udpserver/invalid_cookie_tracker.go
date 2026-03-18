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
)

type invalidCookieTrackerKey struct {
	sessionID      uint8
	expectedCookie uint16
	packetCookie   uint8
	state          uint8
}

type invalidCookieTrackerRecord struct {
	attempts   []int64
	lastEmitAt int64
}

type invalidCookieTracker struct {
	mu      sync.Mutex
	records map[invalidCookieTrackerKey]invalidCookieTrackerRecord
}

const unknownExpectedCookieMarker = 256

func newInvalidCookieTracker() *invalidCookieTracker {
	return &invalidCookieTracker{
		records: make(map[invalidCookieTrackerKey]invalidCookieTrackerRecord, 16),
	}
}

func (t *invalidCookieTracker) Note(sessionID uint8, expectedCookie *uint8, packetCookie uint8, state sessionLookupState, now time.Time, window time.Duration, threshold int) bool {
	if t == nil || window <= 0 || threshold <= 0 {
		return false
	}

	expected := uint16(unknownExpectedCookieMarker)
	if expectedCookie != nil {
		expected = uint16(*expectedCookie)
	}

	nowUnix := now.UnixNano()
	cutoff := now.Add(-window).UnixNano()
	key := invalidCookieTrackerKey{
		sessionID:      sessionID,
		expectedCookie: expected,
		packetCookie:   packetCookie,
		state:          uint8(state),
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	record := t.records[key]
	record.attempts = pruneAttemptTimes(record.attempts, cutoff)
	record.attempts = append(record.attempts, nowUnix)
	if len(record.attempts) < threshold {
		t.records[key] = record
		return false
	}
	if record.lastEmitAt != 0 && nowUnix-record.lastEmitAt < window.Nanoseconds() {
		t.records[key] = record
		return false
	}

	record.lastEmitAt = nowUnix
	t.records[key] = record
	return true
}

func (t *invalidCookieTracker) Cleanup(now time.Time, window time.Duration) {
	if t == nil || window <= 0 {
		return
	}

	cutoff := now.Add(-window).UnixNano()

	t.mu.Lock()
	defer t.mu.Unlock()

	for key, record := range t.records {
		record.attempts = pruneAttemptTimes(record.attempts, cutoff)
		if len(record.attempts) == 0 && (record.lastEmitAt == 0 || record.lastEmitAt < cutoff) {
			delete(t.records, key)
			continue
		}
		t.records[key] = record
	}
}

func pruneAttemptTimes(values []int64, cutoff int64) []int64 {
	if len(values) == 0 {
		return values
	}

	idx := 0
	for idx < len(values) && values[idx] < cutoff {
		idx++
	}
	if idx == 0 {
		return values
	}
	if idx >= len(values) {
		return values[:0]
	}

	copy(values, values[idx:])
	return values[:len(values)-idx]
}
