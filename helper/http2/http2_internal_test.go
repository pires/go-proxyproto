package http2

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
)

// TestServeConn_ConnContextReturnsNil lives in package http2 (not http2_test) so
// it can call the unexported serveConn method directly and recover the panic in
// the same goroutine, which is not possible through the public Serve API because
// Serve spawns a new goroutine per connection.
func TestServeConn_ConnContextReturnsNil(t *testing.T) {
	srv := NewServer(&http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler:           http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}),
		ConnContext: func(_ context.Context, _ net.Conn) context.Context {
			return nil
		},
	}, nil)

	// Create a pipe and write a PROXY header with h2 ALPN to trigger the H2 path.
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	header := proxyproto.Header{
		Version:           2,
		Command:           proxyproto.LOCAL,
		TransportProtocol: proxyproto.UNSPEC,
	}
	if err := header.SetTLVs([]proxyproto.TLV{{
		Type:  proxyproto.PP2_TYPE_ALPN,
		Value: []byte("h2"),
	}}); err != nil {
		t.Fatalf("failed to set TLVs: %v", err)
	}

	// Write the header in a goroutine because net.Pipe is synchronous.
	go func() {
		_, _ = header.WriteTo(clientConn)
		_ = clientConn.Close()
	}()

	pConn := proxyproto.NewConn(serverConn)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic from ConnContext returning nil")
		}
		msg, ok := r.(string)
		if !ok || msg != "ConnContext returned nil" {
			t.Fatalf("expected panic message 'ConnContext returned nil', got: %v", r)
		}
	}()

	_ = srv.serveConn(context.Background(), pConn)
}

func TestServeReturnsErrServerClosedAfterClose(t *testing.T) {
	// Serve should fail before calling Accept when Close/Shutdown has already
	// marked the shared server closed. This avoids accepting new sockets after
	// the user has shut the server down.
	srv := NewServer(&http.Server{
		ReadHeaderTimeout: time.Second,
	}, nil)
	t.Cleanup(func() { _ = srv.h1.Close() })

	if err := srv.closeListeners(); err != nil {
		t.Fatalf("closeListeners: %v", err)
	}

	err := srv.Serve(&stubListener{
		accept: func() (net.Conn, error) {
			t.Fatal("Serve called Accept after the server was closed")
			return nil, net.ErrClosed
		},
	})
	if !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("expected %v, got %v", http.ErrServerClosed, err)
	}
}

func TestServeAcceptErrorPaths(t *testing.T) {
	// Use a fake listener to drive both Accept error branches deterministically:
	// a temporary timeout should be logged and retried, while a later permanent
	// error should be returned to the caller.
	acceptErr := errors.New("accept failed")
	var logBuf bytes.Buffer
	var calls int

	srv := NewServer(&http.Server{
		ReadHeaderTimeout: time.Second,
		ErrorLog:          log.New(&logBuf, "", 0),
	}, nil)
	t.Cleanup(func() { _ = srv.h1.Close() })

	err := srv.Serve(&stubListener{
		accept: func() (net.Conn, error) {
			calls++
			if calls == 1 {
				return nil, timeoutError{err: errors.New("temporary accept timeout")}
			}
			return nil, acceptErr
		},
	})
	if !errors.Is(err, acceptErr) {
		t.Fatalf("expected accept error, got %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected two Accept calls, got %d", calls)
	}
	if !strings.Contains(logBuf.String(), "retrying") {
		t.Fatalf("expected retry log, got %q", logBuf.String())
	}
}

func TestServeReturnsErrServerClosedWhenListenerClosedDuringServe(t *testing.T) {
	// If the listener closes because the server is closing, Serve should normalize
	// the listener error to http.ErrServerClosed, matching net/http semantics.
	srv := NewServer(&http.Server{
		ReadHeaderTimeout: time.Second,
	}, nil)
	t.Cleanup(func() { _ = srv.h1.Close() })

	ln := &stubListener{
		accept: func() (net.Conn, error) {
			if err := srv.closeListeners(); err != nil {
				t.Fatalf("closeListeners: %v", err)
			}
			return nil, net.ErrClosed
		},
	}
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("expected %v, got %v", http.ErrServerClosed, err)
	}
}

func TestCloseListenersReturnsCloseError(t *testing.T) {
	// closeListeners closes every tracked listener and preserves close failures
	// so callers are not told shutdown was clean when a listener refused to close.
	closeErr := errors.New("close failed")
	srv := &Server{
		listeners: map[net.Listener]struct{}{
			&stubListener{close: func() error { return closeErr }}: {},
		},
	}

	if err := srv.closeListeners(); !errors.Is(err, closeErr) {
		t.Fatalf("expected close error, got %v", err)
	}
	if !srv.closed {
		t.Fatal("server was not marked closed")
	}
}

func TestPipeListenerAddrAndDoubleClose(t *testing.T) {
	// Addr is only used for logging/context, but it should still be stable and
	// Close should behave like a normal listener: first close succeeds, repeats
	// report net.ErrClosed.
	ln := newPipeListener()
	addr := ln.Addr()
	if addr.Network() != "pipe" {
		t.Fatalf("unexpected network %q", addr.Network())
	}
	if addr.String() != "pipe" {
		t.Fatalf("unexpected addr string %q", addr.String())
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := ln.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second Close: expected %v, got %v", net.ErrClosed, err)
	}
}

func TestServeConnRejectsUnsupportedProxyALPN(t *testing.T) {
	// A PROXY v2 ALPN TLV selects the downstream protocol. Unknown ALPN values
	// must close the connection and return a useful error instead of silently
	// handing the socket to the HTTP/1 fallback.
	srv := &Server{
		h1: &http.Server{
			ReadHeaderTimeout: time.Second,
			ErrorLog:          log.New(io.Discard, "", 0),
		},
	}

	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	header := proxyproto.Header{
		Version:           2,
		Command:           proxyproto.LOCAL,
		TransportProtocol: proxyproto.UNSPEC,
	}
	if err := header.SetTLVs([]proxyproto.TLV{{
		Type:  proxyproto.PP2_TYPE_ALPN,
		Value: []byte("spdy/3"),
	}}); err != nil {
		t.Fatalf("failed to set TLVs: %v", err)
	}

	go func() {
		_, _ = header.WriteTo(clientConn)
	}()

	err := srv.serveConn(context.Background(), proxyproto.NewConn(serverConn))
	if err == nil || !strings.Contains(err.Error(), `unsupported protocol "spdy/3"`) {
		t.Fatalf("expected unsupported protocol error, got %v", err)
	}
}

func TestServeConnReturnsMalformedProxyTLVError(t *testing.T) {
	// Header parsing deliberately stores raw TLV bytes; the HTTP/2 helper only
	// validates them when it looks for ALPN. This verifies that malformed TLVs are
	// surfaced and the connection is closed in that delayed-validation path.
	srv := &Server{
		h1: &http.Server{
			ReadHeaderTimeout: time.Second,
			ErrorLog:          log.New(io.Discard, "", 0),
		},
	}

	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	go func() {
		_, _ = clientConn.Write(malformedV2LocalTLV())
	}()

	err := srv.serveConn(context.Background(), proxyproto.NewConn(serverConn))
	if !errors.Is(err, proxyproto.ErrTruncatedTLV) {
		t.Fatalf("expected malformed TLV error, got %v", err)
	}
}

func malformedV2LocalTLV() []byte {
	// Construct a syntactically valid v2 LOCAL header whose payload is one byte of
	// raw TLV data. Header parsing accepts it, but Header.TLVs later reports
	// ErrTruncatedTLV because one byte cannot contain a complete TLV tuple.
	header := append([]byte{}, proxyproto.SIGV2...)
	header = append(header, byte(proxyproto.LOCAL), byte(proxyproto.UNSPEC))
	header = append(header, 0, 1)
	header = append(header, byte(proxyproto.PP2_TYPE_ALPN))
	return header
}

type stubListener struct {
	// stubListener lets Serve tests drive precise Accept/Close behavior without
	// binding sockets or depending on OS timing.
	accept func() (net.Conn, error)
	close  func() error
}

func (ln *stubListener) Accept() (net.Conn, error) {
	if ln.accept != nil {
		return ln.accept()
	}
	return nil, net.ErrClosed
}

func (ln *stubListener) Close() error {
	if ln.close != nil {
		return ln.close()
	}
	return nil
}

func (ln *stubListener) Addr() net.Addr {
	return stubAddr("stub")
}

type stubAddr string

func (a stubAddr) Network() string { return string(a) }
func (a stubAddr) String() string  { return string(a) }

type timeoutError struct {
	// timeoutError implements net.Error so Serve takes the retry path used for
	// temporary listener failures such as transient resource exhaustion.
	err error
}

func (e timeoutError) Error() string   { return e.err.Error() }
func (e timeoutError) Unwrap() error   { return e.err }
func (e timeoutError) Timeout() bool   { return true }
func (e timeoutError) Temporary() bool { return true }

// TestServeConnTLSHandshakeFailure pins the tls.Conn branch: a failed
// handshake must close the connection and surface the error.
func TestServeConnTLSHandshakeFailure(t *testing.T) {
	srv := NewServer(&http.Server{ReadHeaderTimeout: 5 * time.Second}, nil)

	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	go func() {
		_, _ = clientConn.Write([]byte("this is not a TLS ClientHello"))
		_ = clientConn.Close()
	}()

	if err := srv.serveConn(context.Background(), tls.Server(serverConn, &tls.Config{})); err == nil {
		t.Fatal("expected TLS handshake error")
	}
}
