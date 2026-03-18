// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"testing"
	"time"
)

func TestInvalidCookieTrackerEmitsOnlyAfterThreshold(t *testing.T) {
	tracker := newInvalidCookieTracker()
	now := time.Now()
	expected := uint8(10)

	if tracker.Note(7, &expected, 22, sessionLookupActive, now, 2*time.Second, 3) {
		t.Fatal("first invalid cookie attempt must not emit")
	}
	if tracker.Note(7, &expected, 22, sessionLookupActive, now.Add(100*time.Millisecond), 2*time.Second, 3) {
		t.Fatal("second invalid cookie attempt must not emit")
	}
	if !tracker.Note(7, &expected, 22, sessionLookupActive, now.Add(200*time.Millisecond), 2*time.Second, 3) {
		t.Fatal("third invalid cookie attempt must emit")
	}
	if tracker.Note(7, &expected, 22, sessionLookupActive, now.Add(300*time.Millisecond), 2*time.Second, 3) {
		t.Fatal("tracker must rate-limit repeated emits inside the same window")
	}
}

func TestInvalidCookieTrackerCleanupRemovesExpiredAttempts(t *testing.T) {
	tracker := newInvalidCookieTracker()
	now := time.Now()
	expected := uint8(10)

	if tracker.Note(7, &expected, 33, sessionLookupActive, now, time.Second, 2) {
		t.Fatal("first invalid cookie attempt must not emit")
	}

	tracker.Cleanup(now.Add(2*time.Second), time.Second)
	if tracker.Note(7, &expected, 33, sessionLookupActive, now.Add(2*time.Second), time.Second, 2) {
		t.Fatal("expired attempts must be cleaned before threshold is reached again")
	}
	if !tracker.Note(7, &expected, 33, sessionLookupActive, now.Add(2100*time.Millisecond), time.Second, 2) {
		t.Fatal("second fresh attempt after cleanup must emit")
	}
}

func TestInvalidCookieTrackerSeparatesClosedSessionState(t *testing.T) {
	tracker := newInvalidCookieTracker()
	now := time.Now()
	expected := uint8(10)

	if tracker.Note(7, &expected, 55, sessionLookupActive, now, time.Second, 2) {
		t.Fatal("first active invalid cookie attempt must not emit")
	}
	if tracker.Note(7, &expected, 55, sessionLookupClosed, now.Add(100*time.Millisecond), time.Second, 2) {
		t.Fatal("closed-session attempts must be tracked separately from active ones")
	}
	if !tracker.Note(7, &expected, 55, sessionLookupClosed, now.Add(200*time.Millisecond), time.Second, 2) {
		t.Fatal("second closed-session attempt should emit for its own bucket")
	}
}
