package http2_test

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"testing"

	"github.com/pires/go-proxyproto"
	h2proxy "github.com/pires/go-proxyproto/helper/http2"
	"golang.org/x/net/http2"
)

func ExampleServer() {
	ln, err := net.Listen("tcp", "localhost:80")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	proxyLn := &proxyproto.Listener{
		Listener: ln,
	}

	server := h2proxy.NewServer(&http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("Hello world!\n"))
		}),
	}, nil)
	if err := server.Serve(proxyLn); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

type contextKey string

const (
	connContextKey = contextKey("conn")
	baseContextKey = contextKey("base")
)

func TestServer_h1(t *testing.T) {
	addr, server := newTestServer(t)
	defer server.Close()

	resp, err := http.Get("http://" + addr)
	if err != nil {
		t.Fatalf("failed to perform HTTP request: %v", err)
	}
	resp.Body.Close()
}

func TestServer_h2(t *testing.T) {
	addr, server := newTestServer(t)
	defer server.Close()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	proxyHeader := proxyproto.Header{
		Version:           2,
		Command:           proxyproto.LOCAL,
		TransportProtocol: proxyproto.UNSPEC,
	}
	tlvs := []proxyproto.TLV{{
		Type:  proxyproto.PP2_TYPE_ALPN,
		Value: []byte("h2"),
	}}
	if err := proxyHeader.SetTLVs(tlvs); err != nil {
		t.Fatalf("failed to set TLVs: %v", err)
	}
	if _, err := proxyHeader.WriteTo(conn); err != nil {
		t.Fatalf("failed to write PROXY header: %v", err)
	}

	h2Conn, err := new(http2.Transport).NewClientConn(conn)
	if err != nil {
		t.Fatalf("failed to create HTTP connection: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "http://"+addr, nil)
	if err != nil {
		t.Fatalf("failed to create HTTP request: %v", err)
	}

	resp, err := h2Conn.RoundTrip(req)
	if err != nil {
		t.Fatalf("failed to perform HTTP request: %v", err)
	}
	resp.Body.Close()
}

func newTestServer(t *testing.T) (addr string, server *http.Server) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	server = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v := r.Context().Value(connContextKey); v == nil {
				t.Errorf("http.Request.Context missing connContextKey")
			}
			if v := r.Context().Value(baseContextKey); v == nil {
				t.Errorf("http.Request.Context missing baseContextKey")
			}
		}),
		BaseContext: func(_ net.Listener) context.Context {
			return context.WithValue(context.Background(), baseContextKey, struct{}{})
		},
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			return context.WithValue(ctx, connContextKey, struct{}{})
		},
	}

	h2Server := h2proxy.NewServer(server, nil)
	done := make(chan error, 1)
	go func() {
		done <- h2Server.Serve(&proxyproto.Listener{Listener: ln})
	}()

	t.Cleanup(func() {
		err := <-done
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("failed to serve: %v", err)
		}
	})

	return ln.Addr().String(), server
}
