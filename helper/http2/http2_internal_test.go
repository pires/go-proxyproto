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
	wirehttp2 "golang.org/x/net/http2"
)

// TestServeConn_ConnContextReturnsNil lives in package http2 (not http2_test) so
// it can call the unexported serveConn method directly and recover the panic in
// the same goroutine, which is not possible through the public Serve API because
// Serve spawns a new goroutine per connection.
func TestServeConn_ConnContextReturnsNil(t *testing.T) {
	srv := NewServerWithConfig(&http.Server{
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
	srv := NewServerWithConfig(&http.Server{
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

	srv := NewServerWithConfig(&http.Server{
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
	srv := NewServerWithConfig(&http.Server{
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
	srv := NewServerWithConfig(&http.Server{ReadHeaderTimeout: 5 * time.Second}, nil)

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

// Verify actual SETTINGS frames so both the compatibility constructor and the
// standard-library constructor serve HTTP/2 and apply their configuration.
func TestServerHTTP2Settings(t *testing.T) {
	for _, tc := range []struct {
		name      string
		newServer func(*http.Server) *Server
		want      uint32
	}{
		{"legacy", func(h1 *http.Server) *Server { return NewServer(h1, nil) }, 0},
		{"standard", func(h1 *http.Server) *Server {
			return NewServerWithConfig(h1, &http.HTTP2Config{MaxConcurrentStreams: 7})
		}, 7},
		{"existing-config", func(h1 *http.Server) *Server {
			h1.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: 9}
			return NewServerWithConfig(h1, nil)
		}, 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h1 := &http.Server{ReadHeaderTimeout: time.Second}
			srv := tc.newServer(h1)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- srv.Serve(&proxyproto.Listener{Listener: ln}) }()
			t.Cleanup(func() {
				_ = h1.Close()
				if err := <-done; !errors.Is(err, http.ErrServerClosed) {
					t.Errorf("Serve: %v", err)
				}
			})
			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			header := proxyproto.Header{Version: 2, Command: proxyproto.LOCAL, TransportProtocol: proxyproto.UNSPEC}
			if err := header.SetTLVs([]proxyproto.TLV{{Type: proxyproto.PP2_TYPE_ALPN, Value: []byte("h2")}}); err != nil {
				t.Fatal(err)
			}
			if _, err := header.WriteTo(conn); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(conn, wirehttp2.ClientPreface); err != nil {
				t.Fatal(err)
			}
			framer := wirehttp2.NewFramer(conn, conn)
			if err := framer.WriteSettings(); err != nil {
				t.Fatal(err)
			}
			frame, err := framer.ReadFrame()
			if err != nil {
				t.Fatal(err)
			}
			settings, ok := frame.(*wirehttp2.SettingsFrame)
			if !ok {
				t.Fatalf("expected SETTINGS, got %T", frame)
			}
			streams, ok := settings.Value(wirehttp2.SettingMaxConcurrentStreams)
			if !ok || streams == 0 || (tc.want != 0 && streams != tc.want) {
				t.Fatalf("MaxConcurrentStreams = %d (present %v), want %d", streams, ok, tc.want)
			}
		})
	}
}

func TestServeConnRejectedHandoffClosesConnection(t *testing.T) {
	// Closing the handoff listener must reject new connections without keeping
	// their prepared contexts or leaving the peer blocked on an open socket.
	srv := &Server{
		h1:       &http.Server{ReadHeaderTimeout: time.Second},
		contexts: make(map[net.Conn]context.Context),
	}
	srv.h1Listener = h1Listener{newPipeListener(), srv}
	if err := srv.h1Listener.pipeListener.Close(); err != nil {
		t.Fatal(err)
	}
	peer, conn := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	t.Cleanup(func() { _ = conn.Close() })

	if err := srv.serveConn(context.Background(), conn); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("serveConn: got %v, want %v", err, net.ErrClosed)
	}
	if len(srv.contexts) != 0 {
		t.Fatalf("rejected connection retained %d contexts", len(srv.contexts))
	}
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		// net.Pipe also reports a closed peer when setting a deadline.
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(err)
		}
	}
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("peer read: got %v, want EOF", err)
	}
}

func TestServeReturnsSetupErrorBeforeAccept(t *testing.T) {
	setupErr := errors.New("HTTP/2 configuration failed")
	srv := &Server{setupErr: setupErr}
	err := srv.Serve(&stubListener{accept: func() (net.Conn, error) {
		t.Fatal("Serve accepted a connection after setup failed")
		return nil, net.ErrClosed
	}})
	if !errors.Is(err, setupErr) {
		t.Fatalf("Serve: got %v, want %v", err, setupErr)
	}
}

func TestServeRejectsNilBaseContext(t *testing.T) {
	peer, conn := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	t.Cleanup(func() { _ = conn.Close() })
	srv := NewServerWithConfig(&http.Server{
		ReadHeaderTimeout: time.Second,
		BaseContext:       func(net.Listener) context.Context { return nil },
	}, nil)
	t.Cleanup(func() { _ = srv.h1.Close() })

	defer func() {
		if got := recover(); got != "BaseContext returned a nil context" {
			t.Fatalf("panic = %v, want nil BaseContext rejection", got)
		}
	}()
	_ = srv.Serve(&stubListener{accept: func() (net.Conn, error) { return conn, nil }})
}
