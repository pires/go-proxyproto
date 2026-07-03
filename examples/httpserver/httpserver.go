// Package main provides a proxyproto HTTP server example.
package main

import (
	"log"
	"net"
	"net/http"
	"time"

	"github.com/pires/go-proxyproto"
	h2proxy "github.com/pires/go-proxyproto/helper/http2"
)

// TODO: add httpclient example

func main() {
	server := http.Server{
		Addr:              ":8080",
		ReadHeaderTimeout: 5 * time.Second,
		ConnState: func(c net.Conn, s http.ConnState) {
			if s == http.StateNew {
				log.Printf("[ConnState] %s -> %s", c.LocalAddr().String(), c.RemoteAddr().String())
			}
		},
		Handler: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			log.Printf("[Handler] remote ip %q", r.RemoteAddr) //nolint:gosec // G706: RemoteAddr is logged intentionally
		}),
	}

	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		panic(err)
	}

	proxyListener := &proxyproto.Listener{
		Listener:          ln,
		ReadHeaderTimeout: 10 * time.Second,
		// This example accepts both proxied and direct connections (e.g. curl
		// against :8080), so the PROXY header is optional. The default policy
		// (REQUIRE) would reject direct connections. Do not expose an
		// optional-header listener to untrusted clients without restricting who
		// may send a header; see the Security section of the README.
		ConnPolicy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			return proxyproto.USE, nil
		},
	}
	defer func() {
		if err := proxyListener.Close(); err != nil {
			log.Printf("failed to close proxy listener: %v", err)
		}
	}()

	// Create an HTTP server which can handle proxied incoming connections for
	// both HTTP/1 and HTTP/2. HTTP/2 support relies on TLS ALPN, the reverse
	// proxy needs to be configured to accept "h2".
	if err := h2proxy.NewServer(&server, nil).Serve(proxyListener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
