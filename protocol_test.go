// This file was shamefully stolen from github.com/armon/go-proxyproto.
// It has been heavily edited to conform to this lib.
//
// Thanks @armon
package proxyproto

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testSourceIPv4Addr is a source IPv4 address used in tests.
const testSourceIPv4Addr string = "10.1.1.1"

// testDestinationIPv4Addr is the destination IPv4 address used in tests.
const testDestinationIPv4Addr string = "20.2.2.2"

// testLocalhostRandomPort is a localhost random port used in tests.
const testLocalhostRandomPort string = "127.0.0.1:0"

// newLocalListener binds a TCP listener on a random localhost port.
func newLocalListener(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", testLocalhostRandomPort)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	return l
}

// testTCPv4Header returns the canonical PROXY TCPv4 header shared across tests.
func testTCPv4Header() *Header {
	return &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: TCPv4,
		SourceAddr: &net.TCPAddr{
			IP:   net.ParseIP(testSourceIPv4Addr),
			Port: 1000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP(testDestinationIPv4Addr),
			Port: 2000,
		},
	}
}

// closeOnCleanup registers c.Close() as a t.Cleanup, failing the test on error.
func closeOnCleanup(t *testing.T, name string, c io.Closer) {
	t.Helper()
	t.Cleanup(func() {
		if closeErr := c.Close(); closeErr != nil {
			t.Errorf("failed to close %s: %v", name, closeErr)
		}
	})
}

// clientConfig parameterizes the standard test client goroutine run by runClient.
type clientConfig struct {
	network     string  // dial network, defaults to "tcp"
	addr        string  // dial target
	header      *Header // written before the payload when set
	payload     []byte  // written after the header; defaults to "ping" when nil, unless headerOnly is set
	headerOnly  bool    // write only the header (if any) and no payload
	expectEcho  []byte  // read back and compared when set
	closeAfter  bool    // close the connection after writing instead of on cleanup
	connectOnly bool    // only dial, write nothing
}

// runClient launches the standard client goroutine and returns a channel that
// is closed on success or receives the first error.
func runClient(t *testing.T, cfg clientConfig) <-chan error {
	t.Helper()
	if cfg.connectOnly && cfg.closeAfter {
		t.Fatalf("runClient: connectOnly and closeAfter are mutually exclusive")
	}
	network := cfg.network
	if network == "" {
		network = "tcp"
	}
	payload := cfg.payload
	if payload == nil && !cfg.headerOnly {
		payload = []byte("ping")
	}

	// Buffered so the goroutine never blocks reporting an error if the test
	// has already failed and stopped reading the channel.
	cliResult := make(chan error, 1)
	go func() {
		conn, err := net.Dial(network, cfg.addr)
		if err != nil {
			cliResult <- err
			return
		}
		// connectOnly never reaches the closeAfter branch below, so it always
		// relies on cleanup; the guard above keeps the two options exclusive.
		if !cfg.closeAfter {
			closeOnCleanup(t, "connection", conn)
		}

		if cfg.connectOnly {
			close(cliResult)
			return
		}

		if cfg.header != nil {
			if _, err := cfg.header.WriteTo(conn); err != nil {
				cliResult <- err
				return
			}
		}

		if len(payload) > 0 {
			if _, err := conn.Write(payload); err != nil {
				cliResult <- err
				return
			}
		}

		if cfg.expectEcho != nil {
			recv := make([]byte, len(cfg.expectEcho))
			if _, err := conn.Read(recv); err != nil {
				cliResult <- err
				return
			}
			if !bytes.Equal(recv, cfg.expectEcho) {
				cliResult <- fmt.Errorf("bad: %v", recv)
				return
			}
		}

		if cfg.closeAfter {
			if err := conn.Close(); err != nil {
				cliResult <- err
				return
			}
		}

		close(cliResult)
	}()

	return cliResult
}

// expectClientOK drains the client result channel and fails on a non-nil error.
func expectClientOK(t *testing.T, ch <-chan error) {
	t.Helper()
	if err := <-ch; err != nil {
		t.Fatalf("client error: %v", err)
	}
}

func TestPassthrough(t *testing.T) {
	l := newLocalListener(t)

	// Header-optional pass-through is opt-in since DefaultPolicy became
	// REQUIRE; this test pins the explicit USE mode.
	pl := &Listener{Listener: l, ConnPolicy: usePolicy}

	cliResult := runClient(t, clientConfig{
		addr:       pl.Addr().String(),
		expectEcho: []byte("pong"),
	})

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	closeOnCleanup(t, "connection", conn)

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}
	expectClientOK(t, cliResult)
}

// TestRequiredWithReadHeaderTimeout will iterate through 3 different timeouts to see
// whether using a REQUIRE policy for a listener would cause an error if the timeout
// is triggerred without a proxy protocol header being defined.
func TestRequiredWithReadHeaderTimeout(t *testing.T) {
	for _, duration := range []int{100, 200, 400} {
		t.Run(fmt.Sprint(duration), func(t *testing.T) {
			start := time.Now()

			l := newLocalListener(t)

			pl := &Listener{
				Listener:          l,
				ReadHeaderTimeout: time.Millisecond * time.Duration(duration),
				Policy: func(_ net.Addr) (Policy, error) {
					return REQUIRE, nil
				},
			}

			cliResult := runClient(t, clientConfig{addr: pl.Addr().String(), connectOnly: true})

			conn, err := pl.Accept()
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			closeOnCleanup(t, "connection", conn)

			// The silent client must make the first Read fail with
			// ErrNoProxyProtocol once the header timeout elapses.
			recv := make([]byte, 4)
			_, err = conn.Read(recv)

			if !errors.Is(err, ErrNoProxyProtocol) {
				t.Fatalf("expected ErrNoProxyProtocol, got %v", err)
			}
			if elapsed := time.Since(start); elapsed < pl.ReadHeaderTimeout {
				t.Fatalf("Read returned before the header timeout: %v < %v", elapsed, pl.ReadHeaderTimeout)
			}
			expectClientOK(t, cliResult)
		})
	}
}

// TestUseWithReadHeaderTimeout will iterate through 3 different timeouts to see
// whether using a USE policy for a listener would not cause an error if the timeout
// is triggerred without a proxy protocol header being defined.
func TestUseWithReadHeaderTimeout(t *testing.T) {
	for _, duration := range []int{100, 200, 400} {
		t.Run(fmt.Sprint(duration), func(t *testing.T) {
			start := time.Now()

			l := newLocalListener(t)

			pl := &Listener{
				Listener:          l,
				ReadHeaderTimeout: time.Millisecond * time.Duration(duration),
				Policy: func(_ net.Addr) (Policy, error) {
					return USE, nil
				},
			}

			cliResult := runClient(t, clientConfig{addr: pl.Addr().String(), connectOnly: true})

			conn, err := pl.Accept()
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			closeOnCleanup(t, "connection", conn)

			// 2 times the ReadHeaderTimeout because the first timeout
			// should occur (the one set on the listener) and allow for the second to follow up
			if err := conn.SetDeadline(time.Now().Add(pl.ReadHeaderTimeout * 2)); err != nil {
				t.Fatalf("err: %v", err)
			}

			// Under USE, timeout-without-header falls through to a raw read of
			// the silent connection, which then hits the conn deadline set above.
			recv := make([]byte, 4)
			_, err = conn.Read(recv)

			var netErr net.Error
			if !errors.As(err, &netErr) || !netErr.Timeout() {
				t.Fatalf("expected the raw read to hit the connection deadline, got %v", err)
			}
			if elapsed := time.Since(start); elapsed < pl.ReadHeaderTimeout {
				t.Fatalf("Read returned before the header timeout: %v < %v", elapsed, pl.ReadHeaderTimeout)
			}
			expectClientOK(t, cliResult)
		})
	}
}

func TestNewConnSetReadHeaderTimeoutOption(t *testing.T) {
	conn, peer := net.Pipe()
	closeOnCleanup(t, "connection", conn)
	closeOnCleanup(t, "peer connection", peer)

	// Ensure SetReadHeaderTimeout sets the connection-specific timeout.
	timeout := 150 * time.Millisecond
	proxyConn := NewConn(conn, SetReadHeaderTimeout(timeout))
	if proxyConn.readHeaderTimeout != timeout {
		t.Fatalf("expected readHeaderTimeout %v, got %v", timeout, proxyConn.readHeaderTimeout)
	}
}

func TestNewConnSetReadHeaderTimeoutIgnoresNegative(t *testing.T) {
	conn, peer := net.Pipe()
	closeOnCleanup(t, "connection", conn)
	closeOnCleanup(t, "peer connection", peer)

	// Negative values are ignored, leaving the NewConn default in place.
	proxyConn := NewConn(conn, SetReadHeaderTimeout(-1))
	if proxyConn.readHeaderTimeout != DefaultReadHeaderTimeout {
		t.Fatalf("expected readHeaderTimeout %v, got %v", DefaultReadHeaderTimeout, proxyConn.readHeaderTimeout)
	}
}

func TestNewConnAppliesDefaultReadHeaderTimeout(t *testing.T) {
	conn, peer := net.Pipe()
	closeOnCleanup(t, "connection", conn)
	closeOnCleanup(t, "peer connection", peer)

	// A bare NewConn is safe-by-default: it applies DefaultReadHeaderTimeout so
	// PROXY header detection is bounded. (Detection only — under the default USE
	// policy the first Read can still block on a silent client; see
	// TestNewConnDefaultTimeoutBoundsHeaderDetection.)
	proxyConn := NewConn(conn)
	if proxyConn.readHeaderTimeout != DefaultReadHeaderTimeout {
		t.Fatalf("expected default readHeaderTimeout %v, got %v", DefaultReadHeaderTimeout, proxyConn.readHeaderTimeout)
	}
}

func TestNewConnSetReadHeaderTimeoutZeroDisables(t *testing.T) {
	conn, peer := net.Pipe()
	closeOnCleanup(t, "connection", conn)
	closeOnCleanup(t, "peer connection", peer)

	// Zero explicitly disables the timeout, overriding the NewConn default.
	proxyConn := NewConn(conn, SetReadHeaderTimeout(0))
	if proxyConn.readHeaderTimeout != 0 {
		t.Fatalf("expected readHeaderTimeout 0 (disabled), got %v", proxyConn.readHeaderTimeout)
	}
}

// TestReadHeaderPreservesHeaderWhenDeadlineRestoreFails locks in the fix where a
// successfully parsed header must not be discarded if restoring the read
// deadline afterwards fails (e.g. a net.Pipe whose peer closed right after
// sending the header).
func TestReadHeaderPreservesHeaderWhenDeadlineRestoreFails(t *testing.T) {
	// A full PROXY v1 header followed by application data.
	data := append([]byte("PROXY TCP4 10.1.1.1 20.2.2.2 1000 2000\r\n"), []byte("ping")...)
	// Succeed the arming SetReadDeadline (call 1), fail the restore (call 2).
	inner := &deadlineFailConn{r: bytes.NewReader(data), failOnSet: 2}

	// NewConn applies DefaultReadHeaderTimeout (> 0), so readHeader arms and then
	// restores a deadline around the header read.
	proxyConn := NewConn(inner)

	header := proxyConn.ProxyHeader()
	if header == nil {
		t.Fatal("header was discarded when the deadline restore failed")
	}
	if got := header.SourceAddr.String(); got != "10.1.1.1:1000" {
		t.Fatalf("unexpected source addr %q", got)
	}
	if inner.setCalls != 2 {
		t.Fatalf("expected arming + restore SetReadDeadline calls, got %d", inner.setCalls)
	}

	// Header processing must not have surfaced the restore error, and the
	// buffered application bytes must still be readable.
	buf := make([]byte, 4)
	n, err := proxyConn.Read(buf)
	if err != nil {
		t.Fatalf("unexpected read error after header: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("expected buffered payload %q, got %q", "ping", string(buf[:n]))
	}
}

// TestNewConnDefaultTimeoutBoundsHeaderDetection verifies what the NewConn
// default actually bounds: PROXY header *detection*. A peer that connects but
// never sends data cannot make header processing block forever. This is
// detection only — under the default (USE) policy a subsequent Read still falls
// through to the raw connection and can block, which is why this test drives
// ProxyHeader, not Read. See TestNewConnRequirePolicyTimeoutUnblocksRead for the
// end-to-end Read bound, which holds only under REQUIRE.
func TestNewConnDefaultTimeoutBoundsHeaderDetection(t *testing.T) {
	orig := DefaultReadHeaderTimeout
	DefaultReadHeaderTimeout = 100 * time.Millisecond
	t.Cleanup(func() { DefaultReadHeaderTimeout = orig })

	conn, peer := net.Pipe()
	closeOnCleanup(t, "connection", conn)
	closeOnCleanup(t, "peer connection", peer)
	// peer never writes.

	proxyConn := NewConn(conn) // no options: the default timeout applies

	done := make(chan *Header, 1)
	start := time.Now()
	go func() { done <- proxyConn.ProxyHeader() }()

	select {
	case header := <-done:
		if header != nil {
			t.Fatalf("expected no header on a silent connection, got %+v", header)
		}
		if elapsed := time.Since(start); elapsed < 50*time.Millisecond {
			t.Fatalf("header detection returned too early (%v); timeout may not have run", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bare NewConn did not bound header detection: ProxyHeader blocked")
	}
}

// TestNewConnRequirePolicyTimeoutUnblocksRead verifies the end-to-end guarantee
// that does hold: under the REQUIRE policy a silent client makes the first Read
// itself return (with ErrNoProxyProtocol) within the header timeout, instead of
// falling through to a blocking raw read as the default (USE) policy does.
func TestNewConnRequirePolicyTimeoutUnblocksRead(t *testing.T) {
	orig := DefaultReadHeaderTimeout
	DefaultReadHeaderTimeout = 100 * time.Millisecond
	t.Cleanup(func() { DefaultReadHeaderTimeout = orig })

	conn, peer := net.Pipe()
	closeOnCleanup(t, "connection", conn)
	closeOnCleanup(t, "peer connection", peer)
	// peer never writes.

	proxyConn := NewConn(conn, WithPolicy(REQUIRE))

	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		buf := make([]byte, 1)
		n, err := proxyConn.Read(buf)
		done <- result{n, err}
	}()

	select {
	case r := <-done:
		if !errors.Is(r.err, ErrNoProxyProtocol) {
			t.Fatalf("expected Read to fail with %v, got n=%d err=%v", ErrNoProxyProtocol, r.n, r.err)
		}
		if elapsed := time.Since(start); elapsed < 50*time.Millisecond {
			t.Fatalf("Read returned too early (%v); timeout may not have run", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("REQUIRE policy: first Read did not return within the header timeout on a silent client")
	}
}

// TestAcceptConcurrentDoesNotRaceOnReadHeaderTimeout runs many Accept calls
// concurrently. Under -race this guards the fix that stopped Accept from writing
// the resolved timeout back onto the shared Listener.
func TestAcceptConcurrentDoesNotRaceOnReadHeaderTimeout(t *testing.T) {
	l := newLocalListener(t)
	// ReadHeaderTimeout unset: every Accept resolves the default concurrently.
	pl := &Listener{Listener: l}

	const n = 8
	errCh := make(chan error, n)
	connCh := make(chan net.Conn, n)

	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			c, err := pl.Accept()
			if err != nil {
				errCh <- err
				return
			}
			connCh <- c
		})
	}

	for range n {
		c, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		_ = c.Close()
	}

	wg.Wait()
	close(errCh)
	close(connCh)
	for err := range errCh {
		t.Fatalf("accept: %v", err)
	}
	for c := range connCh {
		_ = c.Close()
	}
	if pl.ReadHeaderTimeout != 0 {
		t.Fatalf("Accept mutated shared Listener.ReadHeaderTimeout: got %v, want 0", pl.ReadHeaderTimeout)
	}
}

func TestWithBufferSizePositive(t *testing.T) {
	conn, peer := net.Pipe()
	t.Cleanup(func() {
		_ = conn.Close()
		_ = peer.Close()
	})

	proxyConn := NewConn(conn, WithPolicy(USE), WithBufferSize(4096))
	if proxyConn.bufferSize == nil {
		t.Fatalf("expected bufferSize to be set")
	}
	if *proxyConn.bufferSize != 4096 {
		t.Fatalf("expected bufferSize 4096, got %d", *proxyConn.bufferSize)
	}

	go func() { _, _ = peer.Write([]byte("x")) }()
	buf := make([]byte, 1)
	if _, err := proxyConn.Read(buf); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf) != "x" {
		t.Fatalf("unexpected read: %q", buf)
	}
}

func TestWithBufferSizeZeroOrNegative(t *testing.T) {
	for _, length := range []int{0, -1} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			conn, peer := net.Pipe()
			t.Cleanup(func() {
				_ = conn.Close()
				_ = peer.Close()
			})

			proxyConn := NewConn(conn, WithPolicy(USE), WithBufferSize(length))
			if proxyConn.bufferSize != nil {
				t.Fatalf("expected bufferSize to be nil for length %d", length)
			}

			go func() { _, _ = peer.Write([]byte("y")) }()
			buf := make([]byte, 1)
			if _, err := proxyConn.Read(buf); err != nil {
				t.Fatalf("read failed: %v", err)
			}
			if string(buf) != "y" {
				t.Fatalf("unexpected read: %q", buf)
			}
		})
	}
}

func TestListenerReadBufferSizeApplied(t *testing.T) {
	l := newLocalListener(t)
	t.Cleanup(func() { _ = l.Close() })

	pl := &Listener{Listener: l, ReadBufferSize: 4096}

	go func() {
		c, _ := net.Dial("tcp", pl.Addr().String())
		if c != nil {
			_ = c.Close()
		}
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	proxyConn := conn.(*Conn)
	if proxyConn.bufferSize == nil {
		t.Fatalf("expected bufferSize to be set when Listener.ReadBufferSize > 0")
	}
	if *proxyConn.bufferSize != 4096 {
		t.Fatalf("expected bufferSize 4096, got %d", *proxyConn.bufferSize)
	}
}

func TestListenerReadBufferSizeZeroUsesDefault(t *testing.T) {
	l := newLocalListener(t)
	t.Cleanup(func() { _ = l.Close() })

	pl := &Listener{Listener: l, ReadBufferSize: 0}

	go func() {
		c, _ := net.Dial("tcp", pl.Addr().String())
		if c != nil {
			_ = c.Close()
		}
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	proxyConn := conn.(*Conn)
	if proxyConn.bufferSize != nil {
		t.Fatalf("expected bufferSize to be nil when Listener.ReadBufferSize is 0")
	}
}

func TestReadHeaderTimeoutRespectsEarlierDeadline(t *testing.T) {
	const (
		headerTimeout = 200 * time.Millisecond
		userTimeout   = 60 * time.Millisecond
		tolerance     = 100 * time.Millisecond
	)

	l := newLocalListener(t)

	pl := &Listener{
		Listener:          l,
		ReadHeaderTimeout: headerTimeout,
		Policy: func(_ net.Addr) (Policy, error) {
			// Use REQUIRE so a timeout is surfaced as ErrNoProxyProtocol.
			return REQUIRE, nil
		},
	}

	type dialResult struct {
		conn net.Conn
		err  error
	}

	dialResultCh := make(chan dialResult, 1)
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		dialResultCh <- dialResult{conn: conn, err: err}
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	closeOnCleanup(t, "connection", conn)

	result := <-dialResultCh
	if result.err != nil {
		t.Fatalf("client error: %v", result.err)
	}
	closeOnCleanup(t, "client connection", result.conn)

	// Set a shorter user deadline than the readHeaderTimeout and do not send data.
	if err := conn.SetReadDeadline(time.Now().Add(userTimeout)); err != nil {
		t.Fatalf("err: %v", err)
	}

	start := time.Now()
	recv := make([]byte, 1)
	_, err = conn.Read(recv)
	elapsed := time.Since(start)

	// The read should honor the earlier user deadline instead of waiting
	// for the longer readHeaderTimeout.
	if !errors.Is(err, ErrNoProxyProtocol) {
		t.Fatalf("expected ErrNoProxyProtocol, got: %v", err)
	}
	if elapsed > userTimeout+tolerance {
		t.Fatalf("read exceeded user deadline: elapsed=%v timeout=%v", elapsed, userTimeout)
	}
}

func TestDeadlineSettersAfterHeaderProcessed(t *testing.T) {
	conn, peer := net.Pipe()
	closeOnCleanup(t, "connection", conn)
	closeOnCleanup(t, "peer connection", peer)

	proxyConn := NewConn(conn, WithPolicy(USE))

	// Ensure header processing completes by sending a non-PROXY byte
	// and reading it through the proxy connection.
	go func() {
		if _, err := peer.Write([]byte("x")); err != nil {
			t.Errorf("failed to write peer data: %v", err)
		}
	}()
	buf := make([]byte, 1)
	if _, err := proxyConn.Read(buf); err != nil {
		t.Fatalf("read failed: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	if err := proxyConn.SetDeadline(deadline); err != nil {
		t.Fatalf("unexpected SetDeadline error: %v", err)
	}
	if err := proxyConn.SetReadDeadline(deadline); err != nil {
		t.Fatalf("unexpected SetReadDeadline error: %v", err)
	}
	if err := proxyConn.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("unexpected SetWriteDeadline error: %v", err)
	}
}

func TestReadHeaderTimeoutIsReset(t *testing.T) {
	const timeout = time.Millisecond * 250

	l := newLocalListener(t)

	pl := &Listener{
		Listener:          l,
		ReadHeaderTimeout: timeout,
	}

	header := testTCPv4Header()

	cliResult := make(chan error)
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}
		closeOnCleanup(t, "connection", conn)

		// Write out the header!
		if _, err := header.WriteTo(conn); err != nil {
			cliResult <- err
			return
		}

		// Sleep here longer than the configured timeout.
		time.Sleep(timeout * 2)

		if _, err := conn.Write([]byte("ping")); err != nil {
			cliResult <- err
			return
		}
		recv := make([]byte, 4)
		if _, err := conn.Read(recv); err != nil {
			cliResult <- err
			return
		}
		if !bytes.Equal(recv, []byte("pong")) {
			cliResult <- fmt.Errorf("bad: %v", recv)
			return
		}
		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	closeOnCleanup(t, "connection", conn)

	// Set our deadlines higher than our ReadHeaderTimeout
	if err := conn.SetReadDeadline(time.Now().Add(timeout * 3)); err != nil {
		t.Fatalf("err: %v", err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(timeout * 3)); err != nil {
		t.Fatalf("err: %v", err)
	}

	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the remote addr
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if addr.IP.String() != testSourceIPv4Addr {
		t.Fatalf("bad: %v", addr)
	}
	if addr.Port != 1000 {
		t.Fatalf("bad: %v", addr)
	}

	h := conn.(*Conn).ProxyHeader()
	if !h.EqualsTo(header) {
		t.Errorf("bad: %v", h)
	}
	expectClientOK(t, cliResult)
}

func TestAcceptDoesNotMutateListenerReadHeaderTimeout(t *testing.T) {
	l := newLocalListener(t)

	// ReadHeaderTimeout is left unset (0): Accept must resolve the default into
	// the connection without writing it back onto the shared Listener.
	pl := &Listener{Listener: l}

	cliResult := make(chan error, 1)
	go func() {
		c, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}
		closeOnCleanup(t, "client connection", c)
		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	closeOnCleanup(t, "connection", conn)

	if pl.ReadHeaderTimeout != 0 {
		t.Fatalf("Accept mutated Listener.ReadHeaderTimeout: got %v, want 0", pl.ReadHeaderTimeout)
	}
	expectClientOK(t, cliResult)
}

// TestReadHeaderTimeoutIsEmpty ensures the default is set if it is empty.
// The default is 10s, but we delay sending a message, so use 200ms in this test.
// We expect the actual address and port to be returned,
// rather than the ProxyHeader we defined.
func TestReadHeaderTimeoutIsEmpty(t *testing.T) {
	orig := DefaultReadHeaderTimeout
	DefaultReadHeaderTimeout = 200 * time.Millisecond
	t.Cleanup(func() { DefaultReadHeaderTimeout = orig })

	l := newLocalListener(t)

	// The timeout-means-no-header fallback only passes traffic through under
	// an optional-header policy; make that explicit.
	pl := &Listener{
		Listener:   l,
		ConnPolicy: usePolicy,
	}

	header := testTCPv4Header()

	cliResult := make(chan error)
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}
		closeOnCleanup(t, "connection", conn)

		// Sleep here longer than the configured timeout.
		time.Sleep(250 * time.Millisecond)

		// Write out the header!
		if _, err := header.WriteTo(conn); err != nil {
			cliResult <- err
			return
		}

		if _, err := conn.Write([]byte("ping")); err != nil {
			cliResult <- err
			return
		}

		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	closeOnCleanup(t, "connection", conn)

	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the remote addr
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if addr.IP.String() == testSourceIPv4Addr {
		t.Fatalf("bad: %v", addr)
	}
	if addr.Port == 1000 {
		t.Fatalf("bad: %v", addr)
	}
	expectClientOK(t, cliResult)
}

// TestReadHeaderTimeoutIsNegative does the same as above except
// with a negative timeout. Therefore, we expect the right ProxyHeader
// to be returned.
func TestReadHeaderTimeoutIsNegative(t *testing.T) {
	l := newLocalListener(t)

	pl := &Listener{
		Listener:          l,
		ReadHeaderTimeout: -1,
	}

	header := testTCPv4Header()

	cliResult := make(chan error)
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}
		closeOnCleanup(t, "connection", conn)

		// Sleep here longer than the configured timeout.
		time.Sleep(250 * time.Millisecond)

		// Write out the header!
		if _, err := header.WriteTo(conn); err != nil {
			cliResult <- err
			return
		}

		if _, err := conn.Write([]byte("ping")); err != nil {
			cliResult <- err
			return
		}

		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	closeOnCleanup(t, "connection", conn)

	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the remote addr
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if addr.IP.String() != testSourceIPv4Addr {
		t.Fatalf("bad: %v", addr)
	}
	if addr.Port != 1000 {
		t.Fatalf("bad: %v", addr)
	}
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

func TestParse_ipv4(t *testing.T) {
	l := newLocalListener(t)

	pl := &Listener{Listener: l}

	header := testTCPv4Header()

	cliResult := runClient(t, clientConfig{
		addr:       pl.Addr().String(),
		header:     header,
		expectEcho: []byte("pong"),
	})

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	closeOnCleanup(t, "connection", conn)

	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the remote addr
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if addr.IP.String() != testSourceIPv4Addr {
		t.Fatalf("bad: %v", addr)
	}
	if addr.Port != 1000 {
		t.Fatalf("bad: %v", addr)
	}

	h := conn.(*Conn).ProxyHeader()
	if !h.EqualsTo(header) {
		t.Errorf("bad: %v", h)
	}
	expectClientOK(t, cliResult)
}

func TestParse_unixStream(t *testing.T) {
	socketDir := t.TempDir()
	socketPath := filepath.Join(socketDir, "proxy.sock")
	l, err := net.Listen(networkUnix, socketPath)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	closeOnCleanup(t, "listener", l)

	pl := &Listener{Listener: l}

	header := &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: UnixStream,
		SourceAddr: &net.UnixAddr{
			Net:  networkUnix,
			Name: "source.sock",
		},
		DestinationAddr: &net.UnixAddr{
			Net:  networkUnix,
			Name: "dest.sock",
		},
	}

	cliResult := runClient(t, clientConfig{
		network:    networkUnix,
		addr:       socketPath,
		header:     header,
		expectEcho: []byte("pong"),
		closeAfter: true,
	})

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	closeOnCleanup(t, "connection", conn)

	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}

	addr := conn.RemoteAddr().(*net.UnixAddr)
	if addr.Name != header.SourceAddr.(*net.UnixAddr).Name {
		t.Fatalf("bad: %v", addr)
	}

	h := conn.(*Conn).ProxyHeader()
	if !h.EqualsTo(header) {
		t.Errorf("bad: %v", h)
	}

	expectClientOK(t, cliResult)
}

// TestParse_unixDatagramHeaderOverStream parses a unixgram-family v2 header
// carried over a stream pipe; no datagram socket is involved.
func TestParse_unixDatagramHeaderOverStream(t *testing.T) {
	server, client := net.Pipe()
	closeOnCleanup(t, "client", client)
	closeOnCleanup(t, "server", server)

	header := &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: UnixDatagram,
		SourceAddr: &net.UnixAddr{
			Net:  networkUnixgram,
			Name: "source.sock",
		},
		DestinationAddr: &net.UnixAddr{
			Net:  networkUnixgram,
			Name: "dest.sock",
		},
	}

	go func() {
		defer func() {
			if closeErr := client.Close(); closeErr != nil {
				t.Errorf("failed to close client: %v", closeErr)
			}
		}()
		if _, err := header.WriteTo(client); err != nil {
			t.Errorf("failed to write header: %v", err)
		}
		if _, err := client.Write([]byte("ping")); err != nil {
			t.Errorf("failed to write ping: %v", err)
		}
	}()

	conn := NewConn(server)
	recv := make([]byte, 4)
	if _, err := conn.Read(recv); err != nil {
		t.Fatalf("err: %v", err)
	}

	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	remoteAddr := conn.RemoteAddr().(*net.UnixAddr)
	if remoteAddr.Name != header.SourceAddr.(*net.UnixAddr).Name {
		t.Fatalf("bad: %v", remoteAddr)
	}

	localAddr := conn.LocalAddr().(*net.UnixAddr)
	if localAddr.Name != header.DestinationAddr.(*net.UnixAddr).Name {
		t.Fatalf("bad: %v", localAddr)
	}

	h := conn.ProxyHeader()
	if !h.EqualsTo(header) {
		t.Errorf("bad: %v", h)
	}
}

func TestParse_ipv6(t *testing.T) {
	l := newLocalListener(t)

	pl := &Listener{Listener: l}

	header := &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: TCPv6,
		SourceAddr: &net.TCPAddr{
			IP:   net.ParseIP("ffff::ffff"),
			Port: 1000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP("ffff::ffff"),
			Port: 2000,
		},
	}

	cliResult := runClient(t, clientConfig{
		addr:       pl.Addr().String(),
		header:     header,
		expectEcho: []byte("pong"),
	})

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	closeOnCleanup(t, "connection", conn)

	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the remote addr
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if addr.IP.String() != "ffff::ffff" {
		t.Fatalf("bad: %v", addr)
	}
	if addr.Port != 1000 {
		t.Fatalf("bad: %v", addr)
	}

	h := conn.(*Conn).ProxyHeader()
	if !h.EqualsTo(header) {
		t.Errorf("bad: %v", h)
	}
	expectClientOK(t, cliResult)
}

func TestAcceptReturnsErrorWhenPolicyFuncErrors(t *testing.T) {
	l := newLocalListener(t)

	expectedErr := fmt.Errorf("failure")
	policyFunc := func(_ net.Addr) (Policy, error) { return USE, expectedErr }

	pl := &Listener{Listener: l, Policy: policyFunc}

	cliResult := runClient(t, clientConfig{addr: pl.Addr().String(), connectOnly: true})

	conn, err := pl.Accept()
	if err != expectedErr {
		t.Fatalf("Expected error %v, got %v", expectedErr, err)
	}

	if conn != nil {
		t.Fatalf("Expected no connection, got %v", conn)
	}
	expectClientOK(t, cliResult)
}

func TestPanicIfPolicyAndConnPolicySet(t *testing.T) {
	l := newLocalListener(t)

	connPolicyFunc := func(_ ConnPolicyOptions) (Policy, error) { return USE, nil }
	policyFunc := func(_ net.Addr) (Policy, error) { return USE, nil }

	pl := &Listener{Listener: l, ConnPolicy: connPolicyFunc, Policy: policyFunc}

	runClient(t, clientConfig{addr: pl.Addr().String(), connectOnly: true})
	defer func() {
		if r := recover(); r != nil {
			t.Logf("accept did panic as expected: %v", r)
		}
	}()
	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("expected the accept to panic but did not and error is returned, got %v", err)
	}

	if conn != nil {
		t.Fatalf("expected the accept to panic but did not, got %v", conn)
	}
	t.Fatalf("expected the accept to panic but did not")
}

func TestAcceptReturnsErrorWhenConnPolicyFuncErrors(t *testing.T) {
	l := newLocalListener(t)

	expectedErr := fmt.Errorf("failure")
	connPolicyFunc := func(_ ConnPolicyOptions) (Policy, error) { return USE, expectedErr }

	pl := &Listener{Listener: l, ConnPolicy: connPolicyFunc}

	cliResult := runClient(t, clientConfig{addr: pl.Addr().String(), connectOnly: true})

	conn, err := pl.Accept()
	if err != expectedErr {
		t.Fatalf("Expected error %v, got %v", expectedErr, err)
	}

	if conn != nil {
		t.Fatalf("Expected no connection, got %v", conn)
	}
	expectClientOK(t, cliResult)
}

func TestReadingIsRefusedWhenProxyHeaderRequiredButMissing(t *testing.T) {
	l := newLocalListener(t)

	policyFunc := func(_ net.Addr) (Policy, error) { return REQUIRE, nil }

	pl := &Listener{Listener: l, Policy: policyFunc}

	cliResult := runClient(t, clientConfig{addr: pl.Addr().String()})

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	closeOnCleanup(t, "connection", conn)

	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != ErrNoProxyProtocol {
		t.Fatalf("Expected error %v, received %v", ErrNoProxyProtocol, err)
	}
	expectClientOK(t, cliResult)
}

func TestReadingIsRefusedWhenProxyHeaderPresentButNotAllowed(t *testing.T) {
	l := newLocalListener(t)

	policyFunc := func(_ net.Addr) (Policy, error) { return REJECT, nil }

	pl := &Listener{Listener: l, Policy: policyFunc}

	cliResult := runClient(t, clientConfig{
		addr:       pl.Addr().String(),
		header:     testTCPv4Header(),
		headerOnly: true,
	})

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	closeOnCleanup(t, "connection", conn)

	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != ErrSuperfluousProxyHeader {
		t.Fatalf("Expected error %v, received %v", ErrSuperfluousProxyHeader, err)
	}
	expectClientOK(t, cliResult)
}

func TestIgnorePolicyIgnoresIpFromProxyHeader(t *testing.T) {
	l := newLocalListener(t)

	policyFunc := func(_ net.Addr) (Policy, error) { return IGNORE, nil }

	pl := &Listener{Listener: l, Policy: policyFunc}

	cliResult := runClient(t, clientConfig{
		addr:       pl.Addr().String(),
		header:     testTCPv4Header(),
		expectEcho: []byte("pong"),
	})

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	closeOnCleanup(t, "connection", conn)

	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the remote addr
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if addr.IP.String() != "127.0.0.1" {
		t.Fatalf("bad: %v", addr)
	}
	// The header is consumed but must not be exposed under IGNORE: TLV and
	// address consumers see no proxy information at all.
	if h := conn.(*Conn).ProxyHeader(); h != nil {
		t.Fatalf("IGNORE must not expose the parsed header, got %+v", h)
	}
	expectClientOK(t, cliResult)
}

func Test_AllOptionsAreRecognized(t *testing.T) {
	recognizedOpt1 := false
	opt1 := func(_ *Conn) {
		recognizedOpt1 = true
	}

	recognizedOpt2 := false
	opt2 := func(_ *Conn) {
		recognizedOpt2 = true
	}

	server, client := net.Pipe()
	closeOnCleanup(t, "connection", client)

	c := NewConn(server, opt1, opt2)
	if !recognizedOpt1 {
		t.Error("Expected option 1 recognized")
	}

	if !recognizedOpt2 {
		t.Error("Expected option 2 recognized")
	}

	closeOnCleanup(t, "connection", c)
}

// TestReadingIsRefusedOnErrorWhenAddrRequestedFirst pins that poking either
// address accessor before the first Read (which runs header processing under
// the hood) does not swallow the header error the Read must surface.
func TestReadingIsRefusedOnErrorWhenAddrRequestedFirst(t *testing.T) {
	for _, tc := range []struct {
		name string
		poke func(net.Conn)
	}{
		{"RemoteAddr first", func(c net.Conn) { _ = c.RemoteAddr() }},
		{"LocalAddr first", func(c net.Conn) { _ = c.LocalAddr() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newLocalListener(t)
			pl := &Listener{Listener: l, Policy: func(_ net.Addr) (Policy, error) { return REQUIRE, nil }}

			cliResult := runClient(t, clientConfig{addr: pl.Addr().String()})

			conn, err := pl.Accept()
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			closeOnCleanup(t, "connection", conn)

			tc.poke(conn)
			recv := make([]byte, 4)
			if _, err = conn.Read(recv); err != ErrNoProxyProtocol {
				t.Fatalf("Expected error %v, received %v", ErrNoProxyProtocol, err)
			}
			expectClientOK(t, cliResult)
		})
	}
}

func TestSkipProxyProtocolConnPolicy(t *testing.T) {
	l := newLocalListener(t)

	connPolicyFunc := func(_ ConnPolicyOptions) (Policy, error) { return SKIP, nil }

	pl := &Listener{
		Listener:   l,
		ConnPolicy: connPolicyFunc,
	}

	ping := []byte("ping")
	cliResult := runClient(t, clientConfig{addr: pl.Addr().String(), payload: ping})

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	closeOnCleanup(t, "connection", conn)

	_, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatal("err: should be a tcp connection")
	}
	_ = conn.LocalAddr()
	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != nil {
		t.Fatalf("Unexpected read error: %v", err)
	}

	if !bytes.Equal(ping, recv) {
		t.Fatalf("Unexpected %s data while expected %s", recv, ping)
	}

	expectClientOK(t, cliResult)
}

func TestSkipProxyProtocolPolicy(t *testing.T) {
	l := newLocalListener(t)

	policyFunc := func(_ net.Addr) (Policy, error) { return SKIP, nil }

	pl := &Listener{
		Listener: l,
		Policy:   policyFunc,
	}

	ping := []byte("ping")
	cliResult := runClient(t, clientConfig{addr: pl.Addr().String(), payload: ping})

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	closeOnCleanup(t, "connection", conn)

	_, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatal("err: should be a tcp connection")
	}
	_ = conn.LocalAddr()
	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != nil {
		t.Fatalf("Unexpected read error: %v", err)
	}

	if !bytes.Equal(ping, recv) {
		t.Fatalf("Unexpected %s data while expected %s", recv, ping)
	}

	expectClientOK(t, cliResult)
}

func TestLocalCommandUsesUnderlyingAddrs(t *testing.T) {
	l := newLocalListener(t)

	pl := &Listener{Listener: l}

	header := &Header{
		Version:           2,
		Command:           LOCAL,
		TransportProtocol: UNSPEC,
	}

	// closeAfter closes the client side to avoid leaving the connection open.
	cliResult := runClient(t, clientConfig{
		addr:       pl.Addr().String(),
		header:     header,
		closeAfter: true,
	})

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	closeOnCleanup(t, "connection", conn)

	proxyConn := conn.(*Conn)
	// LOCAL should make LocalAddr/RemoteAddr fall back to underlying addresses.
	if proxyConn.LocalAddr().String() != proxyConn.Raw().LocalAddr().String() {
		t.Fatalf("LocalAddr should use underlying address for LOCAL command")
	}
	if proxyConn.RemoteAddr().String() != proxyConn.Raw().RemoteAddr().String() {
		t.Fatalf("RemoteAddr should use underlying address for LOCAL command")
	}

	expectClientOK(t, cliResult)
}

func Test_ConnectionCasts(t *testing.T) {
	l := newLocalListener(t)

	policyFunc := func(_ net.Addr) (Policy, error) { return REQUIRE, nil }

	pl := &Listener{Listener: l, Policy: policyFunc}

	cliResult := runClient(t, clientConfig{addr: pl.Addr().String()})

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	closeOnCleanup(t, "connection", conn)

	proxyprotoConn := conn.(*Conn)
	_, ok := proxyprotoConn.TCPConn()
	if !ok {
		t.Fatal("err: should be a tcp connection")
	}
	_, ok = proxyprotoConn.UDPConn()
	if ok {
		t.Fatal("err: should be a tcp connection not udp")
	}
	_, ok = proxyprotoConn.UnixConn()
	if ok {
		t.Fatal("err: should be a tcp connection not unix")
	}
	_, ok = proxyprotoConn.Raw().(*net.TCPConn)
	if !ok {
		t.Fatal("err: should be a tcp connection")
	}
	expectClientOK(t, cliResult)
}

func Test_ConnectionErrorsWhenHeaderValidationFails(t *testing.T) {
	l := newLocalListener(t)

	validationError := fmt.Errorf("failed to validate")
	pl := &Listener{Listener: l, ValidateHeader: func(*Header) error { return validationError }}

	cliResult := runClient(t, clientConfig{
		addr:       pl.Addr().String(),
		header:     testTCPv4Header(),
		headerOnly: true,
	})

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	closeOnCleanup(t, "connection", conn)

	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != validationError {
		t.Fatalf("expected validation error, got %v", err)
	}
	expectClientOK(t, cliResult)
}

func Test_ConnectionHandlesInvalidUpstreamError(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("error creating listener: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	var connectionCounter atomic.Int32

	newLn := &Listener{
		Listener: l,
		ConnPolicy: func(_ ConnPolicyOptions) (Policy, error) {
			// Return the invalid upstream error on the first call, the listener
			// should remain open and accepting.
			times := connectionCounter.Load()
			if times == 0 {
				connectionCounter.Store(times + 1)
				return REJECT, ErrInvalidUpstream
			}

			return REJECT, ErrNoProxyProtocol
		},
	}

	// Kick off the listener and return any error via the channel.
	errCh := make(chan error, 1)
	go func() {
		_, err := newLn.Accept()
		errCh <- err
	}()

	client := http.Client{Timeout: 200 * time.Millisecond}
	url := "http://" + l.Addr().String()

	// Make two calls to trigger the listener's accept, the first should experience
	// the ErrInvalidUpstream and keep the listener open, the second should experience
	// a different error which will cause the listener to close.

	// First call should experience the ErrInvalidUpstream and keep the listener open.
	resp, err := client.Get(url)
	if resp != nil {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("failed to close response body: %v", closeErr)
		}
	}
	if err != nil && !errors.Is(err, io.EOF) {
		t.Logf("first request failed as expected: %v", err)
	}

	// Ensure the ConnPolicy function was called at least once.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if connectionCounter.Load() >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if connectionCounter.Load() < 1 {
		t.Fatalf("expected ConnPolicy to be called at least once")
	}

	// Ensure nothing came back on the channel: the listener must still be up.
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("invalid upstream shouldn't return an error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		// No error returned (as expected, we're still listening though)
	}

	// Second call should experience a different error and cause the listener to close.
	resp, err = client.Get(url)
	if resp != nil {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("failed to close response body: %v", closeErr)
		}
	}
	if err != nil && !errors.Is(err, io.EOF) {
		t.Logf("second request failed as expected: %v", err)
	}

	// Ensure the listener is closed.
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, ErrNoProxyProtocol) {
			t.Fatalf("unexpected error type: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for listener")
	}
}

type TestTLSServer struct {
	Listener net.Listener

	// TLS is the optional TLS configuration, populated with a new config
	// after TLS is started. If set on an unstarted server before StartTLS
	// is called, existing fields are copied into the new config.
	TLS             *tls.Config
	TLSClientConfig *tls.Config

	// certificate is a parsed version of the TLS config certificate, if present.
	certificate *x509.Certificate
}

func (s *TestTLSServer) Addr() string {
	return s.Listener.Addr().String()
}

func (s *TestTLSServer) Close() error {
	return s.Listener.Close()
}

// based on net/http/httptest/Server.StartTLS.
func NewTestTLSServer(l net.Listener) *TestTLSServer {
	s := &TestTLSServer{}

	cert, err := tls.X509KeyPair(LocalhostCert, LocalhostKey)
	if err != nil {
		panic(fmt.Sprintf("httptest: NewTLSServer: %v", err))
	}
	s.TLS = new(tls.Config)
	if len(s.TLS.Certificates) == 0 {
		s.TLS.Certificates = []tls.Certificate{cert}
	}
	s.certificate, err = x509.ParseCertificate(s.TLS.Certificates[0].Certificate[0])
	if err != nil {
		panic(fmt.Sprintf("NewTestTLSServer: %v", err))
	}
	certpool := x509.NewCertPool()
	certpool.AddCert(s.certificate)
	s.TLSClientConfig = &tls.Config{
		RootCAs:    certpool,
		MinVersion: tls.VersionTLS12,
	}
	s.Listener = tls.NewListener(l, s.TLS)

	return s
}

// Test_TLSServerHeaderInsideTLS covers ordering B: the upstream completes the
// TLS handshake first and only then writes the PROXY header inside the encrypted
// session. TLS must therefore be decrypted before the header can be read, so
// proxyproto wraps the TLS listener (tls INNER, proxyproto OUTER).
func Test_TLSServerHeaderInsideTLS(t *testing.T) {
	l := newLocalListener(t)

	s := NewTestTLSServer(l)
	// tls INNER (set by NewTestTLSServer), proxyproto OUTER.
	s.Listener = &Listener{
		Listener: s.Listener,
		Policy: func(_ net.Addr) (Policy, error) {
			return REQUIRE, nil
		},
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Errorf("failed to close TLS server: %v", err)
		}
	}()

	cliResult := make(chan error)
	go func() {
		conn, err := tls.Dial("tcp", s.Addr(), s.TLSClientConfig)
		if err != nil {
			cliResult <- err
			return
		}
		closeOnCleanup(t, "connection", conn)

		// Write out the header!
		if _, err := testTCPv4Header().WriteTo(conn); err != nil {
			cliResult <- err
			return
		}

		if _, err := conn.Write([]byte("test")); err != nil {
			cliResult <- err
			return
		}

		close(cliResult)
	}()

	conn, err := s.Listener.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	closeOnCleanup(t, "connection", conn)

	recv := make([]byte, 1024)
	n, err := conn.Read(recv)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if string(recv[:n]) != "test" {
		t.Fatalf("expected \"test\", got \"%s\" %v", recv[:n], recv[:n])
	}

	// The header was parsed (from the decrypted stream), so RemoteAddr reports
	// the real client carried by the PROXY header, not the immediate TLS peer.
	if want := net.JoinHostPort(testSourceIPv4Addr, "1000"); conn.RemoteAddr().String() != want {
		t.Fatalf("expected remote addr %q, got %q", want, conn.RemoteAddr())
	}
	expectClientOK(t, cliResult)
}

// Test_TLSServerHeaderBeforeTLS covers ordering A: the upstream sends the PROXY
// header in cleartext before the TLS handshake. proxyproto must read the header
// first, so it wraps the raw listener and TLS wraps proxyproto (proxyproto
// INNER, tls OUTER). This is the common deployment (e.g. AWS NLB proxy protocol
// v2, or HAProxy "send-proxy" in front of a TLS backend).
func Test_TLSServerHeaderBeforeTLS(t *testing.T) {
	l := newLocalListener(t)

	// Reuse the shared cert/config machinery, but invert the nesting so TLS is
	// the outer layer and proxyproto reads the cleartext header first.
	s := NewTestTLSServer(l)
	s.Listener = tls.NewListener(
		&Listener{
			Listener: l,
			Policy:   func(_ net.Addr) (Policy, error) { return REQUIRE, nil },
		},
		s.TLS,
	)
	defer func() {
		if err := s.Close(); err != nil {
			t.Errorf("failed to close TLS server: %v", err)
		}
	}()

	host, _, err := net.SplitHostPort(s.Addr())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	clientTLS := s.TLSClientConfig.Clone()
	clientTLS.ServerName = host

	cliResult := make(chan error)
	go func() {
		raw, err := net.Dial("tcp", s.Addr())
		if err != nil {
			cliResult <- err
			return
		}
		closeOnCleanup(t, "connection", raw)

		// Write the PROXY header in cleartext, THEN start the TLS handshake.
		if _, err := testTCPv4Header().WriteTo(raw); err != nil {
			cliResult <- err
			return
		}

		conn := tls.Client(raw, clientTLS)
		if err := conn.Handshake(); err != nil {
			cliResult <- err
			return
		}
		if _, err := conn.Write([]byte("test")); err != nil {
			cliResult <- err
			return
		}
		close(cliResult)
	}()

	conn, err := s.Listener.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	closeOnCleanup(t, "connection", conn)

	recv := make([]byte, 1024)
	n, err := conn.Read(recv)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if string(recv[:n]) != "test" {
		t.Fatalf("expected \"test\", got %q", recv[:n])
	}

	// The header was parsed from cleartext, so RemoteAddr reports the real client.
	if want := net.JoinHostPort(testSourceIPv4Addr, "1000"); conn.RemoteAddr().String() != want {
		t.Fatalf("expected remote addr %q, got %q", want, conn.RemoteAddr())
	}
	expectClientOK(t, cliResult)
}

func Test_MisconfiguredTLSServerRespondsWithUnderlyingError(t *testing.T) {
	l := newLocalListener(t)

	s := NewTestTLSServer(l)
	s.Listener = &Listener{
		Listener: s.Listener,
		Policy: func(_ net.Addr) (Policy, error) {
			return REQUIRE, nil
		},
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Errorf("failed to close TLS server: %v", err)
		}
	}()

	cliResult := make(chan error)
	go func() {
		// this is not a valid TLS connection, we are
		// connecting to the TLS endpoint via plain TCP.
		//
		// it's an example of a configuration error:
		// client: HTTP  -> PROXY
		// server: PROXY -> TLS -> HTTP
		//
		// we want to bubble up the underlying error,
		// in this case a tls handshake error, instead
		// of responding with a non-descript
		// > "Proxy protocol signature not present".

		conn, err := net.Dial("tcp", s.Addr())
		if err != nil {
			cliResult <- err
			return
		}
		closeOnCleanup(t, "connection", conn)

		// Write out the header!
		if _, err := testTCPv4Header().WriteTo(conn); err != nil {
			cliResult <- err
			return
		}

		if _, err := conn.Write([]byte("GET /foo/bar HTTP/1.1")); err != nil {
			cliResult <- err
			return
		}

		close(cliResult)
	}()

	conn, err := s.Listener.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	closeOnCleanup(t, "connection", conn)

	recv := make([]byte, 1024)
	if _, err = conn.Read(recv); err.Error() != "tls: first record does not look like a TLS handshake" {
		t.Fatalf("expected tls handshake error, got %s", err)
	}
	expectClientOK(t, cliResult)
}

type testConn struct {
	readFromCalledWith io.Reader
	reads              int
	net.Conn           // nil; crash on any unexpected use
}

type deadlineConn struct {
	deadline      time.Time
	readDeadline  time.Time
	writeDeadline time.Time
}

func (c *deadlineConn) Read(_ []byte) (int, error)  { return 0, io.EOF }
func (c *deadlineConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *deadlineConn) Close() error                { return nil }
func (c *deadlineConn) LocalAddr() net.Addr         { return dummyAddr("local") }
func (c *deadlineConn) RemoteAddr() net.Addr        { return dummyAddr("remote") }
func (c *deadlineConn) SetDeadline(t time.Time) error {
	c.deadline = t
	return nil
}
func (c *deadlineConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}
func (c *deadlineConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return nil
}

type noReadFromConn struct {
	written bytes.Buffer
}

func (c *noReadFromConn) Read(_ []byte) (int, error) { return 0, io.EOF }
func (c *noReadFromConn) Write(p []byte) (int, error) {
	return c.written.Write(p)
}
func (c *noReadFromConn) Close() error                { return nil }
func (c *noReadFromConn) LocalAddr() net.Addr         { return dummyAddr("local") }
func (c *noReadFromConn) RemoteAddr() net.Addr        { return dummyAddr("remote") }
func (c *noReadFromConn) SetDeadline(time.Time) error { return nil }
func (c *noReadFromConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *noReadFromConn) SetWriteDeadline(time.Time) error {
	return nil
}

type dummyAddr string

func (a dummyAddr) Network() string { return "dummy" }
func (a dummyAddr) String() string  { return string(a) }

// errDeadlineFail simulates a connection (e.g. a net.Pipe whose peer has closed)
// that rejects SetReadDeadline.
var errDeadlineFail = errors.New("set read deadline failed")

// deadlineFailConn serves a fixed byte stream and can be told to fail a specific
// SetReadDeadline call (1-based, 0 = never). It lets tests reproduce a deadline
// operation that fails after a header has already been parsed.
type deadlineFailConn struct {
	r         *bytes.Reader
	setCalls  int
	failOnSet int
}

func (c *deadlineFailConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *deadlineFailConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *deadlineFailConn) Close() error                { return nil }
func (c *deadlineFailConn) LocalAddr() net.Addr         { return dummyAddr("local") }
func (c *deadlineFailConn) RemoteAddr() net.Addr        { return dummyAddr("remote") }
func (c *deadlineFailConn) SetDeadline(time.Time) error { return nil }
func (c *deadlineFailConn) SetReadDeadline(time.Time) error {
	c.setCalls++
	if c.failOnSet != 0 && c.setCalls == c.failOnSet {
		return errDeadlineFail
	}
	return nil
}
func (c *deadlineFailConn) SetWriteDeadline(time.Time) error { return nil }

func (c *testConn) ReadFrom(r io.Reader) (int64, error) {
	c.readFromCalledWith = r
	b, err := io.ReadAll(r)
	return int64(len(b)), err
}

func (c *testConn) Write(p []byte) (int, error) {
	return len(p), nil
}

func (c *testConn) Read(_ []byte) (int, error) {
	if c.reads == 0 {
		return 0, io.EOF
	}
	c.reads--
	return 1, nil
}

// SetReadDeadline is a no-op so header processing (which now applies the default
// read-header timeout) does not dereference the nil embedded net.Conn.
func (c *testConn) SetReadDeadline(time.Time) error { return nil }

func TestCopyToWrappedConnection(t *testing.T) {
	innerConn := &testConn{}
	wrappedConn := NewConn(innerConn, WithPolicy(USE))
	dummySrc := &testConn{reads: 1}

	if _, err := io.Copy(wrappedConn, dummySrc); err != nil {
		t.Fatalf("err: %v", err)
	}
	if innerConn.readFromCalledWith != dummySrc {
		t.Error("Expected io.Copy to delegate to ReadFrom function of inner destination connection")
	}
}

func TestCopyFromWrappedConnection(t *testing.T) {
	wrappedConn := NewConn(&testConn{reads: 1}, WithPolicy(USE))
	dummyDst := &testConn{}

	if _, err := io.Copy(dummyDst, wrappedConn); err != nil {
		t.Fatalf("err: %v", err)
	}
	if dummyDst.readFromCalledWith != wrappedConn.conn {
		t.Errorf("Expected io.Copy to pass inner source connection to ReadFrom method of destination")
	}
}

func TestCopyFromWrappedConnectionToWrappedConnection(t *testing.T) {
	innerConn1 := &testConn{reads: 1}
	wrappedConn1 := NewConn(innerConn1, WithPolicy(USE))
	innerConn2 := &testConn{}
	wrappedConn2 := NewConn(innerConn2, WithPolicy(USE))

	if _, err := io.Copy(wrappedConn1, wrappedConn2); err != nil {
		t.Fatalf("err: %v", err)
	}
	if innerConn1.readFromCalledWith != innerConn2 {
		t.Errorf("Expected io.Copy to pass inner source connection to ReadFrom of inner destination connection")
	}
}

func TestDeadlineWrappersDelegate(t *testing.T) {
	conn := &deadlineConn{}
	proxyConn := NewConn(conn)

	deadline := time.Now().Add(2 * time.Second)
	readDeadline := time.Now().Add(3 * time.Second)
	writeDeadline := time.Now().Add(4 * time.Second)

	// Ensure deadline setters pass through to the underlying connection.
	if err := proxyConn.SetDeadline(deadline); err != nil {
		t.Fatalf("unexpected SetDeadline error: %v", err)
	}
	if err := proxyConn.SetReadDeadline(readDeadline); err != nil {
		t.Fatalf("unexpected SetReadDeadline error: %v", err)
	}
	if err := proxyConn.SetWriteDeadline(writeDeadline); err != nil {
		t.Fatalf("unexpected SetWriteDeadline error: %v", err)
	}

	if !conn.deadline.Equal(deadline) {
		t.Fatalf("SetDeadline did not pass through value")
	}
	if !conn.readDeadline.Equal(readDeadline) {
		t.Fatalf("SetReadDeadline did not pass through value")
	}
	if !conn.writeDeadline.Equal(writeDeadline) {
		t.Fatalf("SetWriteDeadline did not pass through value")
	}
}

func TestReadFromFallbackCopiesToConn(t *testing.T) {
	conn := &noReadFromConn{}
	proxyConn := NewConn(conn, WithPolicy(USE))

	payload := []byte("payload")
	if _, err := proxyConn.ReadFrom(bytes.NewReader(payload)); err != nil {
		t.Fatalf("unexpected ReadFrom error: %v", err)
	}

	// When the inner connection does not implement io.ReaderFrom,
	// ReadFrom should fall back to io.Copy and write the payload.
	if !bytes.Equal(conn.written.Bytes(), payload) {
		t.Fatalf("unexpected write content: %q", conn.written.String())
	}
}

func TestWriteToDrainsBufferedData(t *testing.T) {
	l := newLocalListener(t)

	pl := &Listener{Listener: l}

	payload := []byte("ping")

	// closeAfter closes the client so WriteTo's io.Copy completes.
	cliResult := runClient(t, clientConfig{
		addr:       pl.Addr().String(),
		header:     testTCPv4Header(),
		payload:    payload,
		closeAfter: true,
	})

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	closeOnCleanup(t, "connection", conn)

	var out bytes.Buffer
	if _, err := conn.(*Conn).WriteTo(&out); err != nil {
		t.Fatalf("unexpected WriteTo error: %v", err)
	}
	if !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("unexpected WriteTo output: %q", out.String())
	}

	expectClientOK(t, cliResult)
}

// chunkedConn wraps a net.Conn and limits reads to simulate TCP chunking.
type chunkedConn struct {
	net.Conn
	maxRead   int
	readCalls int
	bytesRead int
}

func (c *chunkedConn) Read(b []byte) (int, error) {
	if len(b) > c.maxRead {
		b = b[:c.maxRead]
	}
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.readCalls++
		c.bytesRead += n
	}
	return n, err
}

// TestConnReadHandlesChunkedPayload verifies Conn.Read does not drop data
// when the initial TCP read is smaller than the payload.
func TestConnReadHandlesChunkedPayload(t *testing.T) {
	const payloadSize = 400

	proxyHeader := []byte("PROXY TCP4 192.168.1.1 192.168.1.2 12345 443\r\n")
	payload := bytes.Repeat([]byte("X"), payloadSize)
	fullData := append(proxyHeader, payload...)

	serverConn, clientConn := net.Pipe()
	defer func() {
		serverCloseErr := serverConn.Close()
		clientCloseErr := clientConn.Close()
		if serverCloseErr != nil || clientCloseErr != nil {
			t.Errorf("failed to close connection: %v, %v", serverCloseErr, clientCloseErr)
		}
	}()

	go func() {
		_, _ = clientConn.Write(fullData)
		_ = clientConn.Close()
	}()

	// Simulate TCP delivering only 256 bytes in first read.
	chunked := &chunkedConn{Conn: serverConn, maxRead: 256}

	// Create a ProxyProto-wrapped connection.
	conn := NewConn(chunked)
	buf := make([]byte, 64)
	readPayload := make([]byte, 0, payloadSize)
	for len(readPayload) < payloadSize {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			t.Fatalf("unexpected read error: %v", err)
		}
		if n > 0 {
			readPayload = append(readPayload, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
	}

	t.Logf("Sent: %d bytes payload (after %d byte PROXY header)", payloadSize, len(proxyHeader))
	t.Logf("Read: %d bytes", len(readPayload))

	if len(readPayload) != payloadSize {
		t.Fatalf("read %d bytes, expected %d", len(readPayload), payloadSize)
	}
	if !bytes.Equal(readPayload, payload) {
		t.Fatalf("payload mismatch")
	}

	// Ensure the proxy connection read from the underlying conn
	// and drained all bytes, not just buffered reads.
	if chunked.readCalls == 0 {
		t.Fatalf("expected underlying reads to occur")
	}
	if chunked.bytesRead <= len(proxyHeader) {
		t.Fatalf("expected reads beyond header, got %d bytes", chunked.bytesRead)
	}
	if chunked.bytesRead != len(fullData) {
		t.Fatalf("underlying reads=%d bytes, expected %d", chunked.bytesRead, len(fullData))
	}
}

func TestReadUsesConnWhenBufReaderNil(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		if closeErr := serverConn.Close(); closeErr != nil {
			t.Errorf("failed to close server connection: %v", closeErr)
		}
	})
	t.Cleanup(func() {
		if closeErr := clientConn.Close(); closeErr != nil {
			t.Errorf("failed to close client connection: %v", closeErr)
		}
	})

	proxyConn := NewConn(serverConn, WithPolicy(USE))
	sendSecond := make(chan struct{})

	go func() {
		_, _ = clientConn.Write([]byte("a"))
		<-sendSecond
		_, _ = clientConn.Write([]byte("b"))
		_ = clientConn.Close()
	}()

	buf := make([]byte, 1)
	// First read processes header detection and drains the buffer.
	if _, err := proxyConn.Read(buf); err != nil {
		t.Fatalf("first read failed: %v", err)
	}
	if proxyConn.bufReader != nil {
		t.Fatalf("expected bufReader to be nil after draining buffer")
	}

	// With bufReader cleared, Read should use the underlying conn.
	close(sendSecond)
	if _, err := proxyConn.Read(buf); err != nil {
		t.Fatalf("second read failed: %v", err)
	}
	if string(buf) != "b" {
		t.Fatalf("unexpected second read payload: %q", string(buf))
	}
}

func TestWriteToUsesConnWhenBufReaderNil(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		if closeErr := serverConn.Close(); closeErr != nil {
			t.Errorf("failed to close server connection: %v", closeErr)
		}
	})
	t.Cleanup(func() {
		if closeErr := clientConn.Close(); closeErr != nil {
			t.Errorf("failed to close client connection: %v", closeErr)
		}
	})

	proxyConn := NewConn(serverConn, WithPolicy(USE))
	sendPayload := make(chan struct{})

	go func() {
		_, _ = clientConn.Write([]byte("x"))
		<-sendPayload
		_, _ = clientConn.Write([]byte("payload"))
		_ = clientConn.Close()
	}()

	// Process header detection and drain the buffer.
	buf := make([]byte, 1)
	if _, err := proxyConn.Read(buf); err != nil {
		t.Fatalf("initial read failed: %v", err)
	}
	if proxyConn.bufReader != nil {
		t.Fatalf("expected bufReader to be nil after draining buffer")
	}

	// With bufReader cleared, WriteTo should copy directly from conn.
	close(sendPayload)
	var out bytes.Buffer
	if _, err := proxyConn.WriteTo(&out); err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	if out.String() != "payload" {
		t.Fatalf("unexpected WriteTo output: %q", out.String())
	}
}

func benchmarkTCPProxy(size int, b *testing.B) {
	// create and start the echo backend
	backend, err := net.Listen("tcp", testLocalhostRandomPort)
	if err != nil {
		b.Fatalf("err: %v", err)
	}
	b.Cleanup(func() {
		if closeErr := backend.Close(); closeErr != nil {
			b.Errorf("failed to close backend: %v", closeErr)
		}
	})
	go func() {
		for {
			conn, err := backend.Accept()
			if err != nil {
				break
			}
			_, err = io.Copy(conn, conn)
			if err != nil {
				b.Errorf("Failed to read entire payload: %v", err)
				return
			}
			// Can't defer since we keep accepting on each for iteration.
			if closeErr := conn.Close(); closeErr != nil {
				b.Errorf("failed to close connection: %v", closeErr)
				return
			}
		}
	}()

	// start the proxyprotocol enabled tcp proxy
	l, err := net.Listen("tcp", testLocalhostRandomPort)
	if err != nil {
		b.Fatalf("err: %v", err)
	}
	b.Cleanup(func() {
		if closeErr := l.Close(); closeErr != nil {
			b.Errorf("failed to close listener: %v", closeErr)
		}
	})
	pl := &Listener{Listener: l}
	go func() {
		for {
			conn, err := pl.Accept()
			if err != nil {
				break
			}
			bConn, err := net.Dial("tcp", backend.Addr().String())
			if err != nil {
				b.Errorf("failed to dial backend: %v", err)
				return
			}
			go func() {
				_, err = io.Copy(bConn, conn)
				if err != nil {
					b.Errorf("Failed to proxy incoming data to backend: %v", err)
					return
				}
				if closeErr := bConn.(*net.TCPConn).CloseWrite(); closeErr != nil {
					b.Errorf("failed to close write: %v", closeErr)
					return
				}
			}()
			_, err = io.Copy(conn, bConn)
			if err != nil {
				panic(fmt.Sprintf("Failed to proxy data from backend: %v", err))
			}
			if closeErr := conn.Close(); closeErr != nil {
				b.Errorf("failed to close connection: %v", closeErr)
				return
			}
			if closeErr := bConn.Close(); closeErr != nil {
				b.Errorf("failed to close connection: %v", closeErr)
				return
			}
		}
	}()

	data := make([]byte, size)

	header := &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: TCPv4,
		SourceAddr: &net.TCPAddr{
			IP:   net.ParseIP(testSourceIPv4Addr),
			Port: 1000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP(testDestinationIPv4Addr),
			Port: 2000,
		},
	}

	// now for the actual benchmark
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			b.Fatalf("err: %v", err)
		}
		// Write out the header!
		if _, err := header.WriteTo(conn); err != nil {
			b.Fatalf("err: %v", err)
		}
		// send data
		go func() {
			_, err = conn.Write(data)
			if err != nil {
				b.Errorf("Failed to write data: %v", err)
				return
			}
			if closeErr := conn.(*net.TCPConn).CloseWrite(); closeErr != nil {
				b.Errorf("failed to close write: %v", closeErr)
				return
			}
		}()
		// receive data
		n, err := io.Copy(io.Discard, conn)
		if n != int64(len(data)) {
			b.Fatalf("Expected to receive %d bytes, got %d", len(data), n)
		}
		if err != nil {
			b.Fatalf("Failed to read data: %v", err)
		}
		if closeErr := conn.Close(); closeErr != nil {
			b.Errorf("failed to close connection: %v", closeErr)
			return
		}
	}
}

func BenchmarkTCPProxy16KB(b *testing.B) {
	benchmarkTCPProxy(16*1024, b)
}

func BenchmarkTCPProxy32KB(b *testing.B) {
	benchmarkTCPProxy(32*1024, b)
}

func BenchmarkTCPProxy64KB(b *testing.B) {
	benchmarkTCPProxy(64*1024, b)
}

func BenchmarkTCPProxy128KB(b *testing.B) {
	benchmarkTCPProxy(128*1024, b)
}

func BenchmarkTCPProxy256KB(b *testing.B) {
	benchmarkTCPProxy(256*1024, b)
}

func BenchmarkTCPProxy512KB(b *testing.B) {
	benchmarkTCPProxy(512*1024, b)
}

func BenchmarkTCPProxy1024KB(b *testing.B) {
	benchmarkTCPProxy(1024*1024, b)
}

func BenchmarkTCPProxy2048KB(b *testing.B) {
	benchmarkTCPProxy(2048*1024, b)
}

// copied from src/net/http/internal/testcert.go.

// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// LocalhostCert is a PEM-encoded TLS cert with SAN IPs "127.0.0.1" and "[::1]",
// expiring at Jan 29 16:00:00 2084 GMT. Generated from src/crypto/tls:
// go run generate_cert.go  --rsa-bits 1024 --host 127.0.0.1,::1,example.com --ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h.
var LocalhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIICEzCCAXygAwIBAgIQMIMChMLGrR+QvmQvpwAU6zANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMCAXDTcwMDEwMTAwMDAwMFoYDzIwODQwMTI5MTYw
MDAwWjASMRAwDgYDVQQKEwdBY21lIENvMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB
iQKBgQDuLnQAI3mDgey3VBzWnB2L39JUU4txjeVE6myuDqkM/uGlfjb9SjY1bIw4
iA5sBBZzHi3z0h1YV8QPuxEbi4nW91IJm2gsvvZhIrCHS3l6afab4pZBl2+XsDul
rKBxKKtD1rGxlG4LjncdabFn9gvLZad2bSysqz/qTAUStTvqJQIDAQABo2gwZjAO
BgNVHQ8BAf8EBAMCAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUw
AwEB/zAuBgNVHREEJzAlggtleGFtcGxlLmNvbYcEfwAAAYcQAAAAAAAAAAAAAAAA
AAAAATANBgkqhkiG9w0BAQsFAAOBgQCEcetwO59EWk7WiJsG4x8SY+UIAA+flUI9
tyC4lNhbcF2Idq9greZwbYCqTTTr2XiRNSMLCOjKyI7ukPoPjo16ocHj+P3vZGfs
h1fIw3cSS2OolhloGw/XM6RWPWtPAlGykKLciQrBru5NAPvCMsb/I1DAceTiotQM
fblo6RBxUQ==
-----END CERTIFICATE-----`)

// LocalhostKey is the private key for localhostCert.
var LocalhostKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDuLnQAI3mDgey3VBzWnB2L39JUU4txjeVE6myuDqkM/uGlfjb9
SjY1bIw4iA5sBBZzHi3z0h1YV8QPuxEbi4nW91IJm2gsvvZhIrCHS3l6afab4pZB
l2+XsDulrKBxKKtD1rGxlG4LjncdabFn9gvLZad2bSysqz/qTAUStTvqJQIDAQAB
AoGAGRzwwir7XvBOAy5tM/uV6e+Zf6anZzus1s1Y1ClbjbE6HXbnWWF/wbZGOpet
3Zm4vD6MXc7jpTLryzTQIvVdfQbRc6+MUVeLKwZatTXtdZrhu+Jk7hx0nTPy8Jcb
uJqFk541aEw+mMogY/xEcfbWd6IOkp+4xqjlFLBEDytgbIECQQDvH/E6nk+hgN4H
qzzVtxxr397vWrjrIgPbJpQvBsafG7b0dA4AFjwVbFLmQcj2PprIMmPcQrooz8vp
jy4SHEg1AkEA/v13/5M47K9vCxmb8QeD/asydfsgS5TeuNi8DoUBEmiSJwma7FXY
fFUtxuvL7XvjwjN5B30pNEbc6Iuyt7y4MQJBAIt21su4b3sjXNueLKH85Q+phy2U
fQtuUE9txblTu14q3N7gHRZB4ZMhFYyDy8CKrN2cPg/Fvyt0Xlp/DoCzjA0CQQDU
y2ptGsuSmgUtWj3NM9xuwYPm+Z/F84K6+ARYiZ6PYj013sovGKUFfYAqVXVlxtIX
qyUBnu3X9ps8ZfjLZO7BAkEAlT4R5Yl6cGhaJQYZHOde3JEMhNRcVFMO8dJDaFeo
f9Oeos0UUothgiDktdQHxdNEwLjQf7lJJBzV+5OtwswCWA==
-----END RSA PRIVATE KEY-----`)

// TestConnWritePathsSurfaceHeaderError pins that Write, ReadFrom and WriteTo
// surface a header-processing failure the same way Read does: the REQUIRE
// policy with no header on the wire must fail every I/O entry point.
func TestConnWritePathsSurfaceHeaderError(t *testing.T) {
	newFailingConn := func(t *testing.T) *Conn {
		t.Helper()
		conn, peer := net.Pipe()
		t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
		// Non-PROXY bytes on the wire: header detection finds no signature and
		// the REQUIRE policy must fail every I/O entry point.
		go func() { _, _ = peer.Write([]byte("GET / HTTP/1.1\r\n")) }()
		return NewConn(conn, WithPolicy(REQUIRE))
	}

	t.Run("Write", func(t *testing.T) {
		c := newFailingConn(t)
		if _, err := c.Write([]byte("hello")); !errors.Is(err, ErrNoProxyProtocol) {
			t.Fatalf("expected ErrNoProxyProtocol, got %v", err)
		}
	})
	t.Run("ReadFrom", func(t *testing.T) {
		c := newFailingConn(t)
		if _, err := c.ReadFrom(strings.NewReader("hello")); !errors.Is(err, ErrNoProxyProtocol) {
			t.Fatalf("expected ErrNoProxyProtocol, got %v", err)
		}
	})
	t.Run("WriteTo", func(t *testing.T) {
		c := newFailingConn(t)
		if _, err := c.WriteTo(io.Discard); !errors.Is(err, ErrNoProxyProtocol) {
			t.Fatalf("expected ErrNoProxyProtocol, got %v", err)
		}
	})
}

// TestAcceptSurvivesPolicyAddrError is the S3 regression test: a listener
// whose peer addresses cannot be classified as IPs (a Unix socket) combined
// with an address-based policy must drop each such connection and keep
// accepting, not return an error that would stop a typical accept loop.
func TestAcceptSurvivesPolicyAddrError(t *testing.T) {
	// Not t.TempDir(): it embeds the full test name and can exceed the OS limit
	// on Unix socket path length (104 bytes on macOS).
	dir, err := os.MkdirTemp("", "pp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}

	pl := &Listener{
		Listener:   ln,
		ConnPolicy: TrustProxyHeaderFrom(net.ParseIP("10.0.0.1")),
	}
	acceptErr := make(chan error, 1)
	go func() {
		_, err := pl.Accept()
		acceptErr <- err
	}()

	// Every connection on a Unix socket fails IP classification; each must be
	// closed by Accept without Accept returning.
	for range 2 {
		conn, err := net.Dial("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		// The listener closes the connection; a read observing EOF proves it was
		// handled (dropped) rather than left pending.
		buf := make([]byte, 1)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Read(buf); err != io.EOF {
			t.Fatalf("expected connection to be closed by the listener, got %v", err)
		}
		_ = conn.Close()
	}

	select {
	case err := <-acceptErr:
		t.Fatalf("Accept stopped on a policy address error: %v", err)
	default:
	}

	// Accept must still be alive, blocked waiting for the next connection.
	if err := pl.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-acceptErr; err == nil {
		t.Fatal("expected Accept to return the listener-closed error")
	}
}

// limitedFailWriter accepts a fixed number of Write calls, then fails.
type limitedFailWriter struct {
	allowed int
	written bytes.Buffer
}

var errFailWriter = errors.New("writer failed")

func (w *limitedFailWriter) Write(p []byte) (int, error) {
	if w.allowed <= 0 {
		return 0, errFailWriter
	}
	w.allowed--
	return w.written.Write(p)
}

// TestConnWriteToPropagatesWriterErrors pins error propagation from the
// destination writer on both WriteTo stages: flushing the buffered payload and
// streaming the rest of the connection.
func TestConnWriteToPropagatesWriterErrors(t *testing.T) {
	t.Run("buffered flush fails", func(t *testing.T) {
		conn, peer := net.Pipe()
		t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
		go func() {
			_, _ = peer.Write([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 80 443\r\nPAYLOAD"))
		}()

		w := &limitedFailWriter{allowed: 0}
		if _, err := NewConn(conn).WriteTo(w); !errors.Is(err, errFailWriter) {
			t.Fatalf("expected errFailWriter, got %v", err)
		}
	})

	t.Run("streaming copy fails", func(t *testing.T) {
		conn, peer := net.Pipe()
		t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
		go func() {
			// First write carries the header plus a buffered chunk (consumes the
			// writer's single allowed call), the second arrives via io.Copy.
			_, _ = peer.Write([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 80 443\r\nAB"))
			_, _ = peer.Write([]byte("CD"))
		}()

		w := &limitedFailWriter{allowed: 1}
		if _, err := NewConn(conn).WriteTo(w); !errors.Is(err, errFailWriter) {
			t.Fatalf("expected errFailWriter, got %v", err)
		}
		if w.written.String() != "AB" {
			t.Fatalf("buffered flush wrote %q, want \"AB\"", w.written.String())
		}
	})
}

// TestReadHeaderDeadlineSetError pins that a failure to arm the header-read
// deadline (e.g. the connection is already closed) is surfaced instead of
// silently proceeding without the DoS bound.
func TestReadHeaderDeadlineSetError(t *testing.T) {
	conn, peer := net.Pipe()
	_ = peer.Close()
	_ = conn.Close() // SetReadDeadline on a closed pipe fails

	c := NewConn(conn)
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected an error when the deadline cannot be set")
	}
}

// usePolicy is the explicit optional-header policy used by tests that pin the
// historical pass-through behavior.
func usePolicy(ConnPolicyOptions) (Policy, error) { return USE, nil }

// TestDefaultPolicyRequiresHeader pins the spec-conformant default (the
// receiver "MUST not try to guess whether the protocol header is present or
// not"): with nothing configured, a connection that does not open with a
// PROXY header fails its first Read with ErrNoProxyProtocol, for NewConn and
// Listener alike. Setting DefaultPolicy = USE restores the historical
// optional-header behavior.
func TestDefaultPolicyRequiresHeader(t *testing.T) {
	t.Run("NewConn requires a header", func(t *testing.T) {
		conn, peer := net.Pipe()
		t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
		go func() { _, _ = peer.Write([]byte("GET / HTTP/1.1\r\n")) }()

		if _, err := NewConn(conn).Read(make([]byte, 1)); !errors.Is(err, ErrNoProxyProtocol) {
			t.Fatalf("expected ErrNoProxyProtocol, got %v", err)
		}
	})

	t.Run("Listener requires a header", func(t *testing.T) {
		pl := &Listener{Listener: newLocalListener(t)}
		go func() {
			conn, err := net.Dial("tcp", pl.Addr().String())
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("GET / HTTP/1.1\r\n"))
		}()

		conn, err := pl.Accept()
		if err != nil {
			t.Fatalf("accept failed: %v", err)
		}
		closeOnCleanup(t, "connection", conn)
		if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, ErrNoProxyProtocol) {
			t.Fatalf("expected ErrNoProxyProtocol, got %v", err)
		}
	})

	t.Run("DefaultPolicy USE restores pass-through", func(t *testing.T) {
		DefaultPolicy = USE
		defer func() { DefaultPolicy = REQUIRE }()

		conn, peer := net.Pipe()
		t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
		go func() { _, _ = peer.Write([]byte("x")) }()

		buf := make([]byte, 1)
		if _, err := NewConn(conn).Read(buf); err != nil || buf[0] != 'x' {
			t.Fatalf("expected raw pass-through, got (%q, %v)", buf, err)
		}
	})
}

// TestRejectPolicyAllowsHeaderlessConnection pins the REJECT semantics: REJECT
// refuses connections that DO send a PROXY header, but a connection without
// one is served as a raw connection. (Dropping untrusted connections outright
// is TrustProxyHeaderFrom's job, via an ErrInvalidUpstream error.)
func TestRejectPolicyAllowsHeaderlessConnection(t *testing.T) {
	conn, peer := net.Pipe()
	t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
	go func() { _, _ = peer.Write([]byte("raw")) }()

	c := NewConn(conn, WithPolicy(REJECT))
	buf := make([]byte, 3)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("headerless connection under REJECT must pass through, got %v", err)
	}
	if string(buf) != "raw" {
		t.Fatalf("expected raw payload, got %q", buf)
	}
	if h := c.ProxyHeader(); h != nil {
		t.Fatalf("expected no header, got %+v", h)
	}
}

// TestNewConnSkipPolicyConsumesHeaderWithoutUsing pins SKIP semantics on a
// Conn (as opposed to a Listener, where SKIP returns the raw connection): a
// present header is consumed from the stream but discarded — not exposed, not
// validated, and the socket addresses are unaffected.
func TestNewConnSkipPolicyConsumesHeaderWithoutUsing(t *testing.T) {
	conn, peer := net.Pipe()
	t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
	go func() {
		_, _ = testTCPv4Header().WriteTo(peer)
		_, _ = peer.Write([]byte("ping"))
	}()

	c := NewConn(conn, WithPolicy(SKIP))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("expected the payload after the consumed header, got %q", buf)
	}
	if h := c.ProxyHeader(); h != nil {
		t.Fatalf("SKIP must not expose the parsed header, got %+v", h)
	}
	if c.RemoteAddr().String() != conn.RemoteAddr().String() {
		t.Fatalf("SKIP must keep the socket remote address, got %v", c.RemoteAddr())
	}
}

// TestWithBufferSizeTooSmallForV1Header pins the interaction documented on
// WithBufferSize: v1 parsing requires the whole line buffered from a single
// read, so a buffer smaller than the line rejects even a well-behaved v1
// sender. (v2 refills freely and is unaffected.)
func TestWithBufferSizeTooSmallForV1Header(t *testing.T) {
	conn, peer := net.Pipe()
	t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
	go func() {
		// 40-byte v1 line sent atomically; only 16 bytes fit in the buffer.
		_, _ = peer.Write([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 80 443\r\nping"))
	}()

	c := NewConn(conn, WithPolicy(REQUIRE), WithBufferSize(16))
	if _, err := c.Read(make([]byte, 4)); !errors.Is(err, ErrCantReadVersion1Header) {
		t.Fatalf("expected ErrCantReadVersion1Header with an undersized buffer, got %v", err)
	}
}

// TestTrustProxyHeaderFromListener pins the S1 posture end to end on a real
// listener: a trusted peer must send a header (its absence errors instead of
// being guessed around), and an untrusted peer is dropped by Accept without
// stopping the listener.
func TestTrustProxyHeaderFromListener(t *testing.T) {
	t.Run("trusted peer must send a header", func(t *testing.T) {
		pl := &Listener{
			Listener:   newLocalListener(t),
			ConnPolicy: TrustProxyHeaderFrom(net.ParseIP("127.0.0.1")),
		}
		go func() {
			c, err := net.Dial("tcp", pl.Addr().String())
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("raw bytes, no header"))
		}()

		conn, err := pl.Accept()
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		closeOnCleanup(t, "connection", conn)
		if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, ErrNoProxyProtocol) {
			t.Fatalf("expected ErrNoProxyProtocol for a headerless trusted peer, got %v", err)
		}
	})

	t.Run("untrusted peer is dropped, listener survives", func(t *testing.T) {
		pl := &Listener{
			Listener:   newLocalListener(t),
			ConnPolicy: TrustProxyHeaderFrom(net.ParseIP("203.0.113.9")),
		}
		acceptErr := make(chan error, 1)
		go func() {
			_, err := pl.Accept()
			acceptErr <- err
		}()

		c, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		// The listener closes the connection; observing EOF proves it was
		// dropped rather than served.
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("expected the untrusted connection to be closed, got %v", err)
		}
		_ = c.Close()

		select {
		case err := <-acceptErr:
			t.Fatalf("Accept stopped on an untrusted peer: %v", err)
		default:
		}
		if err := pl.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-acceptErr; err == nil {
			t.Fatal("expected Accept to return the listener-closed error")
		}
	})
}
