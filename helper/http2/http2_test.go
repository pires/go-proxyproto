package http2_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	h2proxy "github.com/pires/go-proxyproto/helper/http2"
	"golang.org/x/net/http2"
)

func ExampleServer() {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	proxyLn := &proxyproto.Listener{
		Listener: ln,
	}

	server := h2proxy.NewServer(&http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("Hello world!\n"))
		}),
	}, nil)
	// Run the server in a goroutine.
	go func() {
		if err := server.Serve(proxyLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	time.Sleep(1 * time.Second)

	if err := server.Close(); err != nil {
		log.Fatalf("failed to close server: %v", err)
	}

	// Output:
}

type contextKey string

const (
	connContextKey = contextKey("conn")
	baseContextKey = contextKey("base")
)

func TestServer_h1(t *testing.T) {
	addr, server := newTestServer(t)
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("failed to close server: %v", err)
		}
	})

	resp, err := http.Get("http://" + addr)
	if err != nil {
		t.Fatalf("failed to perform HTTP request: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("failed to close response body: %v", err)
	}
}

func TestServer_h2(t *testing.T) {
	addr, server := newTestServer(t)
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("failed to close server: %v", err)
		}
	})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("failed to close connection: %v", err)
		}
	}()

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
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("failed to close response body: %v", err)
	}
}

func TestServer_h2_tls(t *testing.T) {
	addr, server := newTLSTestServer(t)
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("failed to close server: %v", err)
		}
	})

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // skipping certificate verification for testing.
		NextProtos:         []string{http2.NextProtoTLS},
	})
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("failed to close connection: %v", err)
		}
	}()

	h2Conn, err := new(http2.Transport).NewClientConn(conn)
	if err != nil {
		t.Fatalf("failed to create HTTP connection: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "https://"+addr, nil)
	if err != nil {
		t.Fatalf("failed to create HTTP request: %v", err)
	}

	resp, err := h2Conn.RoundTrip(req)
	if err != nil {
		t.Fatalf("failed to perform HTTP request: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Errorf("failed to close response body: %v", err)
	}
}

func TestServer_h1_nil_ConnContext(t *testing.T) {
	addr, server := newTestServerWithoutConnContext(t)
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("failed to close server: %v", err)
		}
	})

	resp, err := http.Get("http://" + addr)
	if err != nil {
		t.Fatalf("failed to perform HTTP request: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("failed to close response body: %v", err)
	}
}

func TestServer_h2_nil_ConnContext(t *testing.T) {
	addr, server := newTestServerWithoutConnContext(t)
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("failed to close server: %v", err)
		}
	})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("failed to close connection: %v", err)
		}
	}()

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
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("failed to close response body: %v", err)
	}
}

func newTestServer(t *testing.T) (addr string, server *http.Server) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	server = &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
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
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
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
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("failed to serve: %v", err)
		}
	})

	return ln.Addr().String(), server
}

func newTLSTestServer(t *testing.T) (addr string, server *http.Server) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	server = &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
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
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return context.WithValue(ctx, connContextKey, struct{}{})
		},
	}

	tlsLn := tls.NewListener(ln, testTLSConfig(t))
	h2Server := h2proxy.NewServer(server, nil)
	done := make(chan error, 1)
	go func() {
		done <- h2Server.Serve(tlsLn)
	}()

	t.Cleanup(func() {
		err := <-done
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("failed to serve: %v", err)
		}
	})

	return ln.Addr().String(), server
}

func newTestServerWithoutConnContext(t *testing.T) (addr string, server *http.Server) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	server = &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler:           http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}),
	}

	h2Server := h2proxy.NewServer(server, nil)
	done := make(chan error, 1)
	go func() {
		done <- h2Server.Serve(&proxyproto.Listener{Listener: ln})
	}()

	t.Cleanup(func() {
		err := <-done
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("failed to serve: %v", err)
		}
	})

	return ln.Addr().String(), server
}

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("failed to generate serial: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{http2.NextProtoTLS},
	}
}
