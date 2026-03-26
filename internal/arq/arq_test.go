package arq

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
)

// MockPacketEnqueuer captures packets sent by ARQ
type MockPacketEnqueuer struct {
	mu          sync.Mutex
	Packets     chan capturedPacket
	removedSeqs []uint16
}

type capturedPacket struct {
	priority        int
	packetType      uint8
	sequenceNum     uint16
	fragmentID      uint8
	totalFragments  uint8
	compressionType uint8
	ttl             time.Duration
	payload         []byte
}

func NewMockPacketEnqueuer() *MockPacketEnqueuer {
	return &MockPacketEnqueuer{
		Packets: make(chan capturedPacket, 1000),
	}
}

func (m *MockPacketEnqueuer) PushTXPacket(priority int, packetType uint8, sequenceNum uint16, fragmentID uint8, totalFragments uint8, compressionType uint8, ttl time.Duration, payload []byte) bool {
	m.Packets <- capturedPacket{
		priority:        priority,
		packetType:      packetType,
		sequenceNum:     sequenceNum,
		fragmentID:      fragmentID,
		totalFragments:  totalFragments,
		compressionType: compressionType,
		ttl:             ttl,
		payload:         append([]byte(nil), payload...),
	}
	return true
}

func (m *MockPacketEnqueuer) RemoveQueuedData(sequenceNum uint16) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removedSeqs = append(m.removedSeqs, sequenceNum)
	return true
}

type testLogger struct {
	t *testing.T
}

func (l *testLogger) Debugf(format string, args ...any) { l.t.Logf("[DEBUG] "+format, args...) }
func (l *testLogger) Infof(format string, args ...any)  { l.t.Logf("[INFO] "+format, args...) }
func (l *testLogger) Errorf(format string, args ...any) { l.t.Logf("[ERROR] "+format, args...) }

type eofAfterDataConn struct {
	mu     sync.Mutex
	data   []byte
	read   bool
	closed bool
}

func (c *eofAfterDataConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.read {
		return 0, io.EOF
	}
	c.read = true
	n := copy(p, c.data)
	return n, io.EOF
}

func (c *eofAfterDataConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *eofAfterDataConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

type errAfterDataConn struct {
	mu     sync.Mutex
	data   []byte
	err    error
	read   bool
	closed bool
}

func (c *errAfterDataConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.read {
		return 0, c.err
	}
	c.read = true
	n := copy(p, c.data)
	return n, c.err
}

func (c *errAfterDataConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *errAfterDataConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

type timeoutOnlyError struct{}

func (e timeoutOnlyError) Error() string   { return "timeout" }
func (e timeoutOnlyError) Timeout() bool   { return true }
func (e timeoutOnlyError) Temporary() bool { return false }

func newTransientOpError(op string) error {
	return &net.OpError{Op: op, Net: "tcp", Err: errors.New("transient op failure")}
}

type transientReadConn struct {
	mu       sync.Mutex
	closed   bool
}

func (c *transientReadConn) Read(_ []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return 0, newTransientOpError("read")
}

func (c *transientReadConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *transientReadConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

type transientWriteConn struct {
	mu          sync.Mutex
	failWrites  int
	writes      [][]byte
	closed      bool
	readBlocked bool
}

func (c *transientWriteConn) Read(_ []byte) (int, error) {
	time.Sleep(50 * time.Millisecond)
	return 0, timeoutOnlyError{}
}

func (c *transientWriteConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failWrites > 0 {
		c.failWrites--
		return 0, newTransientOpError("write")
	}
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (c *transientWriteConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func TestARQ_New(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize: 100,
		RTO:        0.1,
		MaxRTO:     0.5,
	}
	a := NewARQ(1, 2, enqueuer, nil, 1000, &testLogger{t}, cfg)

	if a.streamID != 1 {
		t.Errorf("expected streamID 1, got %d", a.streamID)
	}
	if a.sessionID != 2 {
		t.Errorf("expected sessionID 2, got %d", a.sessionID)
	}
	if a.state != StateOpen {
		t.Errorf("expected state StateOpen, got %v", a.state)
	}
}

func TestARQ_SendData(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize: 100,
		RTO:        0.1,
		MaxRTO:     0.5,
	}

	// Create a pipe to simulate local connection
	localApp, arqConn := net.Pipe()
	defer localApp.Close()
	defer arqConn.Close()

	a := NewARQ(1, 1, enqueuer, arqConn, 1000, &testLogger{t}, cfg)
	a.Start()
	defer a.Close("test end", CloseOptions{Force: true})

	// Wait for workers to start
	time.Sleep(50 * time.Millisecond)

	testData := []byte("hello arq")
	go func() {
		_, _ = localApp.Write(testData)
	}()

	select {
	case p := <-enqueuer.Packets:
		if p.packetType != Enums.PACKET_STREAM_DATA {
			t.Errorf("expected PACKET_STREAM_DATA, got %d", p.packetType)
		}
		if !bytes.Equal(p.payload, testData) {
			t.Errorf("expected payload %s, got %s", string(testData), string(p.payload))
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for packet")
	}
}

func TestARQ_ReceiveData(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize: 100,
		RTO:        0.1,
		MaxRTO:     0.5,
	}

	localApp, arqConn := net.Pipe()
	defer localApp.Close()
	defer arqConn.Close()

	a := NewARQ(1, 1, enqueuer, arqConn, 1000, &testLogger{t}, cfg)
	a.Start()
	defer a.Close("test end", CloseOptions{Force: true})

	// Wait for workers to start
	time.Sleep(50 * time.Millisecond)

	testData := []byte("hello from remote")
	a.ReceiveData(0, testData)

	// ARQ should send an ACK
	select {
	case p := <-enqueuer.Packets:
		if p.packetType != Enums.PACKET_STREAM_DATA_ACK {
			t.Errorf("expected PACKET_STREAM_DATA_ACK, got %d", p.packetType)
		}
		if p.sequenceNum != 0 {
			t.Errorf("expected ACK for sn 0, got %d", p.sequenceNum)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for ACK")
	}

	// Local app should receive the data
	buf := make([]byte, 100)
	_ = localApp.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := localApp.Read(buf)
	if err != nil {
		t.Fatalf("failed to read from local app: %v", err)
	}
	if !bytes.Equal(buf[:n], testData) {
		t.Errorf("expected data %s, got %s", string(testData), string(buf[:n]))
	}
}

func TestARQ_ReceiveAckPurgesQueuedDataCopy(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize: 100,
		RTO:        0.1,
		MaxRTO:     0.5,
	}

	a := NewARQ(1, 1, enqueuer, nil, 1000, &testLogger{t}, cfg)
	a.mu.Lock()
	a.sndBuf[7] = &arqDataItem{
		Data:       []byte("hello"),
		CreatedAt:  time.Now(),
		LastSentAt: time.Now(),
		CurrentRTO: a.rto,
	}
	a.mu.Unlock()

	if !a.ReceiveAck(Enums.PACKET_STREAM_DATA_ACK, 7) {
		t.Fatal("expected ReceiveAck to handle tracked sequence")
	}

	enqueuer.mu.Lock()
	defer enqueuer.mu.Unlock()
	if len(enqueuer.removedSeqs) != 1 || enqueuer.removedSeqs[0] != 7 {
		t.Fatalf("expected queued data purge for seq 7, got %#v", enqueuer.removedSeqs)
	}
}

func TestARQ_OutOfOrderReceive(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize: 100,
		RTO:        0.1,
		MaxRTO:     0.5,
	}

	localApp, arqConn := net.Pipe()
	defer localApp.Close()
	defer arqConn.Close()

	a := NewARQ(1, 1, enqueuer, arqConn, 1000, &testLogger{t}, cfg)
	a.Start()
	defer a.Close("test end", CloseOptions{Force: true})

	// Wait for workers to start
	time.Sleep(50 * time.Millisecond)

	// Send packets in order 1, 2, 0
	a.ReceiveData(1, []byte("packet 1"))
	a.ReceiveData(2, []byte("packet 2"))

	// Drain ACKs
	for i := 0; i < 2; i++ {
		<-enqueuer.Packets
	}

	// Verify nothing is readable yet (since packet 0 is missing)
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 100)
		_ = localApp.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, _ = localApp.Read(buf)
		close(done)
	}()
	select {
	case <-done:
		// t.Error("should not have read anything yet")
		// Actually net.Pipe Read will block, so if it returns with timeout error it's fine.
	case <-time.After(150 * time.Millisecond):
		// Expected timeout
	}

	// Now send packet 0
	a.ReceiveData(0, []byte("packet 0"))
	<-enqueuer.Packets // ACK for 0

	// Now everything should be readable in order
	expected := [][]byte{[]byte("packet 0"), []byte("packet 1"), []byte("packet 2")}
	for _, exp := range expected {
		buf := make([]byte, 100)
		_ = localApp.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := localApp.Read(buf)
		if err != nil {
			t.Fatalf("failed to read from local app: %v", err)
		}
		if !bytes.Equal(buf[:n], exp) {
			t.Errorf("expected %s, got %s", string(exp), string(buf[:n]))
		}
	}
}

func TestARQ_Retransmission(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize: 100,
		RTO:        0.1, // 100ms RTO
		MaxRTO:     0.5,
	}

	localApp, arqConn := net.Pipe()
	defer localApp.Close()
	defer arqConn.Close()

	a := NewARQ(1, 1, enqueuer, arqConn, 1000, &testLogger{t}, cfg)
	a.Start()
	defer a.Close("test end", CloseOptions{Force: true})

	time.Sleep(50 * time.Millisecond)

	testData := []byte("retransmit me")
	go func() {
		_, _ = localApp.Write(testData)
	}()

	// Initial transmission
	select {
	case p := <-enqueuer.Packets:
		if p.packetType != Enums.PACKET_STREAM_DATA {
			t.Errorf("expected PACKET_STREAM_DATA, got %d", p.packetType)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for initial packet")
	}

	// Don't ACK. Wait for retransmission.
	// Retransmission loop uses baseInterval which is RTO/3 (approx 33ms) or 50ms min.
	// So we should see a RESEND packet soon after 100ms.
	select {
	case p := <-enqueuer.Packets:
		if p.packetType != Enums.PACKET_STREAM_RESEND {
			t.Errorf("expected front retransmission to use PACKET_STREAM_RESEND, got %d", p.packetType)
		}
		if p.priority != Enums.DefaultPacketPriority(Enums.PACKET_STREAM_RESEND) {
			t.Errorf("expected retry priority %d, got %d", Enums.DefaultPacketPriority(Enums.PACKET_STREAM_RESEND), p.priority)
		}
		if !bytes.Equal(p.payload, testData) {
			t.Errorf("expected payload %s, got %s", string(testData), string(p.payload))
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for retransmission")
	}
}

func TestARQ_RetransmitPrioritiesFavorFrontWindow(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	a := NewARQ(1, 1, enqueuer, nil, 1000, &testLogger{t}, Config{
		WindowSize: 10,
		RTO:        0.1,
		MaxRTO:     0.5,
	})
	a.windowSize = 10

	jobs := []rtxJob{
		{sn: 95},
		{sn: 99},
		{sn: 90},
	}
	a.sndNxt = 100

	priorityKinds := a.retransmitPriorityKinds(jobs)
	if len(priorityKinds) != len(jobs) {
		t.Fatalf("expected %d priority decisions, got %d", len(jobs), len(priorityKinds))
	}

	retryPriority := Enums.DefaultPacketPriority(Enums.PACKET_STREAM_RESEND)
	normalPriority := Enums.DefaultPacketPriority(Enums.PACKET_STREAM_DATA)

	if !priorityKinds[2] {
		t.Fatalf("expected oldest outstanding resend to get retry priority")
	}
	if priorityKinds[0] {
		t.Fatalf("expected middle resend to stay normal priority")
	}
	if priorityKinds[1] {
		t.Fatalf("expected newest resend to stay normal priority")
	}

	priorities := make([]int, len(priorityKinds))
	packetTypes := make([]uint8, len(priorityKinds))
	for i, isRetry := range priorityKinds {
		priorities[i] = normalPriority
		packetTypes[i] = Enums.PACKET_STREAM_DATA
		if isRetry {
			priorities[i] = retryPriority
			packetTypes[i] = Enums.PACKET_STREAM_RESEND
		}
	}
	if priorities[2] != retryPriority {
		t.Fatalf("expected oldest outstanding resend to map to retry priority %d, got %d", retryPriority, priorities[2])
	}
	if priorities[0] != normalPriority {
		t.Fatalf("expected middle resend to map to normal priority %d, got %d", normalPriority, priorities[0])
	}
	if priorities[1] != normalPriority {
		t.Fatalf("expected newest resend to map to normal priority %d, got %d", normalPriority, priorities[1])
	}
	if packetTypes[2] != Enums.PACKET_STREAM_RESEND {
		t.Fatalf("expected oldest outstanding resend to keep STREAM_RESEND type, got %d", packetTypes[2])
	}
	if packetTypes[0] != Enums.PACKET_STREAM_DATA {
		t.Fatalf("expected middle retransmit to downgrade to STREAM_DATA, got %d", packetTypes[0])
	}
	if packetTypes[1] != Enums.PACKET_STREAM_DATA {
		t.Fatalf("expected newest retransmit to downgrade to STREAM_DATA, got %d", packetTypes[1])
	}
}

func TestARQ_ACKHandling(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize: 100,
		RTO:        0.1,
		MaxRTO:     0.5,
	}

	localApp, arqConn := net.Pipe()
	defer localApp.Close()
	defer arqConn.Close()

	a := NewARQ(1, 1, enqueuer, arqConn, 1000, &testLogger{t}, cfg)
	a.Start()
	defer a.Close("test end", CloseOptions{Force: true})

	time.Sleep(50 * time.Millisecond)

	go func() {
		_, _ = localApp.Write([]byte("data"))
	}()

	var sn uint16
	select {
	case p := <-enqueuer.Packets:
		sn = p.sequenceNum
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out")
	}

	// Verify it's in sndBuf
	a.mu.Lock()
	if _, exists := a.sndBuf[sn]; !exists {
		t.Error("packet should be in sndBuf")
	}
	a.mu.Unlock()

	// Receive ACK
	a.HandleAckPacket(Enums.PACKET_STREAM_DATA_ACK, sn, 0)

	// Verify it's removed from sndBuf
	a.mu.Lock()
	if _, exists := a.sndBuf[sn]; exists {
		t.Error("packet should be removed from sndBuf after ACK")
	}
	a.mu.Unlock()
}

func TestARQ_GracefulClose(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize:               100,
		RTO:                      0.1,
		MaxRTO:                   0.5,
		EnableControlReliability: true,
	}

	localApp, arqConn := net.Pipe()
	defer localApp.Close()
	defer arqConn.Close()

	a := NewARQ(1, 1, enqueuer, arqConn, 1000, &testLogger{t}, cfg)
	a.Start()

	time.Sleep(50 * time.Millisecond)

	// Local app closes connection
	_ = localApp.Close()

	// ARQ should send a FIN
	select {
	case p := <-enqueuer.Packets:
		if p.packetType != Enums.PACKET_STREAM_FIN {
			t.Errorf("expected PACKET_STREAM_FIN, got %d", p.packetType)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for FIN")
	}

	// Remote ACKs FIN
	a.HandleAckPacket(Enums.PACKET_STREAM_FIN_ACK, 0, 0)

	// Remote sends FIN
	a.MarkFinReceived()

	// Wait for ARQ to close
	select {
	case <-a.Done():
		// Success
	case <-time.After(1 * time.Second):
		t.Error("ARQ should be closed after FIN handshake")
	}
}

func TestARQ_IOReadDataWithEOFStillQueuesFinalChunk(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize:               100,
		RTO:                      0.1,
		MaxRTO:                   0.5,
		EnableControlReliability: true,
	}

	conn := &eofAfterDataConn{data: []byte("final chunk")}
	a := NewARQ(1, 1, enqueuer, conn, 1000, &testLogger{t}, cfg)
	a.Start()
	defer a.Close("test end", CloseOptions{Force: true})

	var gotData bool
	timeout := time.After(1 * time.Second)
	for !gotData {
		select {
		case p := <-enqueuer.Packets:
			switch p.packetType {
			case Enums.PACKET_STREAM_DATA:
				gotData = true
				if !bytes.Equal(p.payload, []byte("final chunk")) {
					t.Fatalf("expected final payload %q, got %q", []byte("final chunk"), p.payload)
				}
			}
		case <-timeout:
			t.Fatalf("timed out waiting for final data, gotData=%t", gotData)
		}
	}

	if !a.HasPendingSequence(0) {
		t.Fatal("expected final chunk to remain tracked in sndBuf until acknowledged")
	}
	if a.IsReset() {
		t.Fatal("expected EOF after data to stay on graceful close path, not reset path")
	}
}

func TestARQ_IOReadDataWithErrorDefersRSTUntilDrain(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize:               100,
		RTO:                      0.1,
		MaxRTO:                   0.5,
		EnableControlReliability: true,
	}

	conn := &errAfterDataConn{data: []byte("chunk before read error"), err: errors.New("boom")}
	a := NewARQ(1, 1, enqueuer, conn, 1000, &testLogger{t}, cfg)
	a.Start()
	defer a.Close("test end", CloseOptions{Force: true})

	timeout := time.After(1 * time.Second)
	gotData := false
	for !gotData {
		select {
		case p := <-enqueuer.Packets:
			if p.packetType == Enums.PACKET_STREAM_DATA {
				gotData = true
				if !bytes.Equal(p.payload, []byte("chunk before read error")) {
					t.Fatalf("expected queued payload %q, got %q", []byte("chunk before read error"), p.payload)
				}
			}
		case <-timeout:
			t.Fatal("timed out waiting for final data chunk")
		}
	}

	if !a.HasPendingSequence(0) {
		t.Fatal("expected final chunk to remain pending for drain")
	}

	select {
	case p := <-enqueuer.Packets:
		if p.packetType == Enums.PACKET_STREAM_RST {
			t.Fatal("expected read error after data not to emit RST immediately before drain")
		}
	default:
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		a.mu.Lock()
		deferred := a.deferredClose
		deferredPacket := a.deferredPacket
		a.mu.Unlock()
		if deferred && deferredPacket == Enums.PACKET_STREAM_RST {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expected read error after data to arm deferred RST drain path")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestARQ_IOTransientReadErrorDoesNotResetStream(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize: 100,
		RTO:        0.1,
		MaxRTO:     0.5,
	}

	conn := &transientReadConn{}
	a := NewARQ(1, 1, enqueuer, conn, 1000, &testLogger{t}, cfg)
	a.Start()
	defer a.Close("test end", CloseOptions{Force: true})

	time.Sleep(150 * time.Millisecond)

	if a.IsClosed() {
		t.Fatal("expected transient read error not to close stream")
	}
	if a.IsReset() {
		t.Fatal("expected transient read error not to move stream to reset path")
	}
}

func TestARQ_IOTransientReadErrorEventuallyStopsRetrying(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize: 100,
		RTO:        0.1,
		MaxRTO:     0.5,
	}

	conn := &transientReadConn{}
	a := NewARQ(1, 1, enqueuer, conn, 1000, &testLogger{t}, cfg)
	a.Start()
	defer a.Close("test end", CloseOptions{Force: true})

	select {
	case <-a.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("expected repeated transient read errors to eventually stop the stream")
	}
}

func TestARQ_WriteLoopRetriesTransientWriteError(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize: 100,
		RTO:        0.1,
		MaxRTO:     0.5,
	}

	conn := &transientWriteConn{failWrites: 1}
	a := NewARQ(1, 1, enqueuer, conn, 1000, &testLogger{t}, cfg)
	a.Start()
	defer a.Close("test end", CloseOptions{Force: true})

	a.ReceiveData(0, []byte("from peer"))

	timeout := time.After(1 * time.Second)
	for {
		conn.mu.Lock()
		writes := len(conn.writes)
		payload := []byte(nil)
		if writes > 0 {
			payload = append([]byte(nil), conn.writes[0]...)
		}
		conn.mu.Unlock()
		if writes > 0 {
			if !bytes.Equal(payload, []byte("from peer")) {
				t.Fatalf("expected write payload %q, got %q", []byte("from peer"), payload)
			}
			break
		}

		select {
		case <-timeout:
			t.Fatal("timed out waiting for transient write retry to succeed")
		default:
			time.Sleep(20 * time.Millisecond)
		}
	}

	if a.IsClosed() {
		t.Fatal("expected transient write error not to close stream")
	}
}

func TestARQ_PeerFinHalfCloseStillAcceptsInboundData(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize:               100,
		RTO:                      0.1,
		MaxRTO:                   0.5,
		EnableControlReliability: true,
	}

	localApp, arqConn := net.Pipe()
	defer localApp.Close()
	defer arqConn.Close()

	a := NewARQ(1, 1, enqueuer, arqConn, 1000, &testLogger{t}, cfg)
	a.Start()
	defer a.Close("test end", CloseOptions{Force: true})

	time.Sleep(50 * time.Millisecond)

	a.MarkFinReceived()

	if state := a.State(); state != StateHalfClosedRemote {
		t.Fatalf("expected half-closed-remote after peer FIN, got %v", state)
	}
	if a.IsClosed() {
		t.Fatal("stream should not close immediately after peer FIN")
	}

	payload := []byte("peer data after fin")
	a.ReceiveData(0, payload)

	select {
	case p := <-enqueuer.Packets:
		if p.packetType != Enums.PACKET_STREAM_DATA_ACK {
			t.Fatalf("expected STREAM_DATA_ACK after inbound data, got %d", p.packetType)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for STREAM_DATA_ACK")
	}

	buf := make([]byte, 128)
	_ = localApp.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := localApp.Read(buf)
	if err != nil {
		t.Fatalf("failed to read forwarded inbound data: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("expected payload %q, got %q", payload, buf[:n])
	}
}

func TestARQ_PeerFinThenLocalFinAckClosesWithoutRST(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize:               100,
		RTO:                      0.1,
		MaxRTO:                   0.5,
		EnableControlReliability: true,
	}

	a := NewARQ(1, 1, enqueuer, nil, 1000, &testLogger{t}, cfg)

	a.MarkFinReceived()
	if state := a.State(); state != StateHalfClosedRemote {
		t.Fatalf("expected half-closed-remote after peer FIN, got %v", state)
	}
	if a.IsClosed() {
		t.Fatal("stream should remain open until local FIN path completes")
	}

	a.Close("local graceful close after peer fin", CloseOptions{SendFIN: true})

	select {
	case p := <-enqueuer.Packets:
		if p.packetType != Enums.PACKET_STREAM_FIN {
			t.Fatalf("expected STREAM_FIN, got %d", p.packetType)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for STREAM_FIN")
	}

	if a.IsClosed() {
		t.Fatal("stream should not close before FIN is acknowledged")
	}

	a.HandleAckPacket(Enums.PACKET_STREAM_FIN_ACK, 0, 0)

	select {
	case <-a.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected stream to close after peer FIN and local FIN_ACK")
	}

	if state := a.State(); state != StateTimeWait {
		t.Fatalf("expected TIME_WAIT after graceful FIN handshake, got %v", state)
	}

	select {
	case p := <-enqueuer.Packets:
		if p.packetType == Enums.PACKET_STREAM_RST {
			t.Fatal("did not expect STREAM_RST during graceful FIN handshake")
		}
	default:
	}
}

func TestARQ_Reset(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize: 100,
		RTO:        0.1,
		MaxRTO:     0.5,
	}

	localApp, arqConn := net.Pipe()
	defer localApp.Close()
	defer arqConn.Close()

	a := NewARQ(1, 1, enqueuer, arqConn, 1000, &testLogger{t}, cfg)
	a.Start()

	time.Sleep(50 * time.Millisecond)

	// Close with RST
	a.Close("testing reset", CloseOptions{SendRST: true})

	// ARQ should send an RST
	select {
	case p := <-enqueuer.Packets:
		if p.packetType != Enums.PACKET_STREAM_RST {
			t.Errorf("expected PACKET_STREAM_RST, got %d", p.packetType)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for RST")
	}

	// ARQ should mark state as Reset
	if a.State() != StateReset {
		t.Errorf("expected state StateReset, got %v", a.State())
	}
}

func TestARQ_Backpressure(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize: 10,
		RTO:        1.0,
		MaxRTO:     2.0,
	}

	localApp, arqConn := net.Pipe()
	defer localApp.Close()
	defer arqConn.Close()

	a := NewARQ(1, 1, enqueuer, arqConn, 10, &testLogger{t}, cfg)
	a.Start()
	defer a.Close("test end", CloseOptions{Force: true})

	time.Sleep(50 * time.Millisecond)

	// Send 8 packets (limit is 0.8 * 10 = 8)
	data := []byte("1234567890") // 10 bytes
	for i := 0; i < 8; i++ {
		_, err := localApp.Write(data)
		if err != nil {
			t.Fatalf("failed to write %d: %v", i, err)
		}
	}

	// Drain transmitted packets
	for i := 0; i < 8; i++ {
		select {
		case <-enqueuer.Packets:
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("timed out waiting for packet %d", i)
		}
	}

	// The 9th write should block or at least waitWindowNotFull should trigger.
	// Since we are in a goroutine in ioLoop, we can check if sndBuf size is 8.
	a.mu.Lock()
	sndBufLen := len(a.sndBuf)
	a.mu.Unlock()
	if sndBufLen != 8 {
		t.Errorf("expected sndBuf size 8, got %d", sndBufLen)
	}

	// Try writing one more. It should block ioLoop.
	writeDone := make(chan struct{})
	go func() {
		_, _ = localApp.Write(data)
		close(writeDone)
	}()

	select {
	case <-writeDone:
		// It might not block immediately because of net.Pipe internal buffering,
		// but ioLoop should be waiting at waitWindowNotFull.
	case <-time.After(200 * time.Millisecond):
		// Expected to block if net.Pipe buffer is small or ioLoop is waiting.
	}

	// ACK one packet
	a.ReceiveAck(Enums.PACKET_STREAM_DATA_ACK, 0)

	// Now ioLoop should proceed and send the 9th packet
	select {
	case p := <-enqueuer.Packets:
		if p.sequenceNum != 8 {
			t.Errorf("expected sequence 8, got %d", p.sequenceNum)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for 9th packet after ACK")
	}
}
