package http2

import (
	"context"
	"net"
	"net/http"
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
