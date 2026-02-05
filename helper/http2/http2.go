// Package http2 provides helpers for HTTP/2.
package http2

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"
	"golang.org/x/net/http2"
)

const listenerRetryBaseDelay = 5 * time.Millisecond

// Server is an HTTP server accepting both regular and proxied, both HTTP/1 and
// HTTP/2 connections.
//
// HTTP/2 is negotiated using TLS ALPN, either directly via a tls.Conn, either
// indirectly via the PROXY protocol. When the PROXY protocol is used, the
// TLS-terminating proxy in front of the server must be configured to accept
// the "h2" TLS ALPN protocol.
//
// The server is closed when the http.Server is.
type Server struct {
	h1         *http.Server  // regular HTTP/1 server
	h2         *http2.Server // HTTP/2 server
	h2Err      error         // HTTP/2 server setup error, if any
	h1Listener h1Listener    // pipe listener for the HTTP/1 server

	// The following fields are protected by the mutex
	mu        sync.Mutex
	closed    bool
	listeners map[net.Listener]struct{}
}

// NewServer creates a new HTTP server.
//
// A nil h2 is equivalent to a zero http2.Server.
func NewServer(h1 *http.Server, h2 *http2.Server) *Server {
	if h2 == nil {
		h2 = new(http2.Server)
	}
	srv := &Server{
		h1:        h1,
		h2:        h2,
		h2Err:     http2.ConfigureServer(h1, h2),
		listeners: make(map[net.Listener]struct{}),
	}
	srv.h1Listener = h1Listener{newPipeListener(), srv}
	go func() {
		// proxyListener.Accept never fails
		_ = h1.Serve(srv.h1Listener)
	}()
	return srv
}

func (srv *Server) errorLog() *log.Logger {
	if srv.h1.ErrorLog != nil {
		return srv.h1.ErrorLog
	}
	return log.Default()
}

// Serve accepts incoming connections on the listener ln.
func (srv *Server) Serve(ln net.Listener) error {
	if srv.h2Err != nil {
		return srv.h2Err
	}

	srv.mu.Lock()
	ok := !srv.closed
	if ok {
		srv.listeners[ln] = struct{}{}
	}
	srv.mu.Unlock()
	if !ok {
		return http.ErrServerClosed
	}

	defer func() {
		srv.mu.Lock()
		delete(srv.listeners, ln)
		srv.mu.Unlock()
	}()

	// net.Listener.Accept can fail for temporary failures, e.g. too many open
	// files or other timeout conditions. In that case, wait and retry later.
	// This mirrors what the net/http package does.
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			if delay == 0 {
				delay = listenerRetryBaseDelay
			} else {
				delay *= 2
			}
			if maxDelay := 1 * time.Second; delay > maxDelay {
				delay = maxDelay
			}
			srv.errorLog().Printf("listener %q: accept error (retrying in %v): %v", ln.Addr(), delay, err)
			time.Sleep(delay)
		} else if err != nil {
			if srv.isClosed() {
				return http.ErrServerClosed
			}
			return fmt.Errorf("failed to accept connection: %w", err)
		}

		delay = 0

		baseCtx := context.Background()
		if srv.h1.BaseContext != nil {
			baseCtx = srv.h1.BaseContext(ln)
		}

		go func(baseCtx context.Context, conn net.Conn) {
			if err := srv.serveConn(baseCtx, conn); err != nil {
				srv.errorLog().Printf("listener %q: %v", ln.Addr(), err)
			}
		}(baseCtx, conn)
	}
}

func (srv *Server) serveConn(baseCtx context.Context, conn net.Conn) error {
	var proto string
	switch conn := conn.(type) {
	case *tls.Conn:
		if err := conn.Handshake(); err != nil {
			if closeErr := conn.Close(); closeErr != nil {
				srv.errorLog().Printf("failed to close connection: %v", closeErr)
			}
			return err
		}
		proto = conn.ConnectionState().NegotiatedProtocol
	case *proxyproto.Conn:
		if proxyHeader := conn.ProxyHeader(); proxyHeader != nil {
			tlvs, err := proxyHeader.TLVs()
			if err != nil {
				if closeErr := conn.Close(); closeErr != nil {
					srv.errorLog().Printf("failed to close connection: %v", closeErr)
				}
				return err
			}
			for _, tlv := range tlvs {
				if tlv.Type == proxyproto.PP2_TYPE_ALPN {
					proto = string(tlv.Value)
					break
				}
			}
		}
	}

	// See https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
	switch proto {
	case http2.NextProtoTLS, "h2c":
		defer func() {
			if closeErr := conn.Close(); closeErr != nil {
				srv.errorLog().Printf("failed to close connection: %v", closeErr)
			}
		}()

		ctx := baseCtx
		// We don't check if srv.h1.ConnContext is nil so http.Server works the same
		// with or without this middleware.
		// For more info, see https://github.com/pires/go-proxyproto/pull/140/changes#r2725568706.
		if connCtx := srv.h1.ConnContext(ctx, conn); connCtx != nil {
			ctx = connCtx
		}

		opts := http2.ServeConnOpts{Context: ctx, BaseConfig: srv.h1}
		srv.h2.ServeConn(conn, &opts)
		return nil
	case "", "http/1.0", "http/1.1":
		return srv.h1Listener.ServeConn(conn)
	default:
		if closeErr := conn.Close(); closeErr != nil {
			srv.errorLog().Printf("failed to close connection: %v", closeErr)
		}
		return fmt.Errorf("unsupported protocol %q", proto)
	}
}

func (srv *Server) closeListeners() error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	srv.closed = true

	var err error
	for ln := range srv.listeners {
		if cerr := ln.Close(); cerr != nil {
			err = cerr
		}
	}
	return err
}

func (srv *Server) isClosed() bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return srv.closed
}

// h1Listener is used to signal back http.Server's Close and Shutdown to the
// HTTP/2 server.
type h1Listener struct {
	*pipeListener
	srv *Server
}

func (ln h1Listener) Close() error {
	// pipeListener.Close never fails
	_ = ln.pipeListener.Close()
	return ln.srv.closeListeners()
}
