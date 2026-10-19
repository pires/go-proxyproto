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
	h1          *http.Server // shared HTTP/1 and HTTP/2 server
	setupErr    error
	serveHTTP2  func(context.Context, net.Conn)
	h1Listener  h1Listener // connection handoff to net/http
	baseContext func(net.Listener) context.Context
	connContext func(context.Context, net.Conn) context.Context

	// The following fields are protected by the mutex
	mu        sync.Mutex
	closed    bool
	listeners map[net.Listener]struct{}
	contexts  map[net.Conn]context.Context
}

// NewServer creates an HTTP server using the legacy x/net HTTP/2 configuration.
// A nil h2 is equivalent to a zero http2.Server.
//
// Deprecated: Use NewServerWithConfig with net/http.HTTP2Config instead.
func NewServer(h1 *http.Server, h2 *http2.Server) *Server {
	if h2 == nil {
		h2 = new(http2.Server)
	}
	err := http2.ConfigureServer(h1, h2)
	srv := newServer(h1, func(ctx context.Context, conn net.Conn) {
		defer func() { _ = conn.Close() }()
		h2.ServeConn(conn, &http2.ServeConnOpts{Context: ctx, BaseConfig: h1})
	})
	srv.setupErr = err
	return srv
}

// NewServerWithConfig creates an HTTP server using standard-library HTTP/2.
// A non-nil h2 overrides h1.HTTP2. Otherwise h1.HTTP2 is preserved.
// Configure h1 before calling NewServerWithConfig; the helper installs its
// context hooks and enables HTTP/1, TLS HTTP/2, and unencrypted HTTP/2.
func NewServerWithConfig(h1 *http.Server, h2 *http.HTTP2Config) *Server {
	if h2 != nil {
		h1.HTTP2 = h2
	}
	h1.Protocols = new(http.Protocols)
	h1.Protocols.SetHTTP1(true)
	h1.Protocols.SetHTTP2(true)
	h1.Protocols.SetUnencryptedHTTP2(true)
	return newServer(h1, nil)
}

func newServer(h1 *http.Server, serveHTTP2 func(context.Context, net.Conn)) *Server {
	srv := &Server{
		h1:          h1,
		serveHTTP2:  serveHTTP2,
		listeners:   make(map[net.Listener]struct{}),
		contexts:    make(map[net.Conn]context.Context),
		baseContext: h1.BaseContext,
		connContext: h1.ConnContext,
	}
	// Contexts are prepared using the original listener and connection before
	// handing connections to net/http. Keep *tls.Conn intact for TLS ALPN.
	h1.BaseContext = nil
	h1.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
		srv.mu.Lock()
		prepared, ok := srv.contexts[conn]
		delete(srv.contexts, conn)
		srv.mu.Unlock()
		if ok {
			return prepared
		}
		return ctx
	}
	srv.h1Listener = h1Listener{newPipeListener(), srv}
	go func() {
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
	if srv.setupErr != nil {
		return srv.setupErr
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
			// Retry Accept after a temporary listener error. There is no
			// connection to serve on this iteration.
			continue
		} else if err != nil {
			if srv.isClosed() {
				return http.ErrServerClosed
			}
			return fmt.Errorf("failed to accept connection: %w", err)
		}

		delay = 0

		baseCtx := context.Background()
		if srv.baseContext != nil {
			baseCtx = srv.baseContext(ln)
			if baseCtx == nil {
				panic("BaseContext returned a nil context")
			}
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
	case "h2", "h2c", "", "http/1.0", "http/1.1":
		ctx := context.WithValue(baseCtx, http.ServerContextKey, srv.h1)
		if cc := srv.connContext; cc != nil {
			ctx = cc(ctx, conn)
			if ctx == nil {
				panic("ConnContext returned nil")
			}
		}
		if (proto == "h2" || proto == "h2c") && srv.serveHTTP2 != nil {
			srv.serveHTTP2(ctx, conn)
			return nil
		}
		srv.mu.Lock()
		srv.contexts[conn] = ctx
		srv.mu.Unlock()
		if err := srv.h1Listener.ServeConn(conn); err != nil {
			srv.mu.Lock()
			delete(srv.contexts, conn)
			srv.mu.Unlock()
			_ = conn.Close()
			return err
		}
		return nil
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
