# go-proxyproto

[![Actions Status](https://github.com/pires/go-proxyproto/workflows/test/badge.svg)](https://github.com/pires/go-proxyproto/actions)
[![Coverage Status](https://coveralls.io/repos/github/pires/go-proxyproto/badge.svg?branch=main)](https://coveralls.io/github/pires/go-proxyproto?branch=main)
[![Go Report Card](https://goreportcard.com/badge/github.com/pires/go-proxyproto)](https://goreportcard.com/report/github.com/pires/go-proxyproto)
[![](https://godoc.org/github.com/pires/go-proxyproto?status.svg)](https://pkg.go.dev/github.com/pires/go-proxyproto?tab=doc)


A Go library implementation of the [PROXY protocol, versions 1 and 2](https://www.haproxy.org/download/2.3/doc/proxy-protocol.txt),
which provides, as per specification:
> (...) a convenient way to safely transport connection
> information such as a client's address across multiple layers of NAT or TCP
> proxies. It is designed to require little changes to existing components and
> to limit the performance impact caused by the processing of the transported
> information.

This library is to be used in one of or both proxy clients and proxy servers that need to support said protocol.
Both protocol versions, 1 (text-based) and 2 (binary-based) are supported.

## Installation

```shell
$ go get -u github.com/pires/go-proxyproto
```

## Examples

The fastest way to get started is the runnable programs under
[`examples/`](examples) and the API examples on
[pkg.go.dev](https://pkg.go.dev/github.com/pires/go-proxyproto#pkg-examples):

| Goal | Where to look |
| ---- | ------------- |
| Minimal client | [`examples/client`](examples/client) |
| Minimal server | [`examples/server`](examples/server) |
| HTTP server | [`examples/httpserver`](examples/httpserver) |
| Server + client over TLS (PROXY header before TLS) | [`examples/tlsserver`](examples/tlsserver), [`examples/tlsclient`](examples/tlsclient) |
| `Listener` options: timeout, buffer size, policy, validation | [`ExampleListener_*`](https://pkg.go.dev/github.com/pires/go-proxyproto#example-Listener) |
| `NewConn` options | [`ExampleNewConn_*`](https://pkg.go.dev/github.com/pires/go-proxyproto#example-NewConn) |
| PROXY over TLS, both wrapping orders | [`ExampleListener_tls`](https://pkg.go.dev/github.com/pires/go-proxyproto#example-Listener-Tls), [`ExampleListener_tlsHeaderInsideTLS`](https://pkg.go.dev/github.com/pires/go-proxyproto#example-Listener-TlsHeaderInsideTLS) |

## Usage

### Client

```go
package main

import (
	"io"
	"log"
	"net"

	proxyproto "github.com/pires/go-proxyproto"
)

func chkErr(err error) {
	if err != nil {
		log.Fatalf("Error: %s", err.Error())
	}
}

func main() {
	// Dial some proxy listener e.g. https://github.com/mailgun/proxyproto
	target, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9876")
	chkErr(err)

	conn, err := net.DialTCP("tcp", nil, target)
	chkErr(err)

	defer conn.Close()

	// Create a proxyprotocol header or use HeaderProxyFromAddrs() if you
	// have two conn's
	header := &proxyproto.Header{
		Version:           1,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.TCPv4,
		SourceAddr: &net.TCPAddr{
			IP:   net.ParseIP("10.1.1.1"),
			Port: 1000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP("20.2.2.2"),
			Port: 2000,
		},
	}
	// After the connection was created write the proxy headers first
	_, err = header.WriteTo(conn)
	chkErr(err)
	// Then your data... e.g.:
	_, err = io.WriteString(conn, "HELO")
	chkErr(err)
}
```

### Server

```go
package main

import (
	"log"
	"net"

	proxyproto "github.com/pires/go-proxyproto"
)

func main() {
	// Create a listener
	addr := "localhost:9876"
	list, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("couldn't listen to %q: %q\n", addr, err.Error())
	}

	// Wrap listener in a proxyproto listener
	proxyListener := &proxyproto.Listener{Listener: list}
	defer proxyListener.Close()

	// Wait for a connection and accept it
	conn, err := proxyListener.Accept()
	if err != nil {
		log.Fatalf("failed to accept connection: %v", err)
	}
	defer conn.Close()

	// Print connection details
	if conn.LocalAddr() == nil {
		log.Fatal("couldn't retrieve local address")
	}
	log.Printf("local address: %q", conn.LocalAddr().String())

	if conn.RemoteAddr() == nil {
		log.Fatal("couldn't retrieve remote address")
	}
	log.Printf("remote address: %q", conn.RemoteAddr().String())
}
```

### HTTP Server
```go
package main

import (
	"net"
	"net/http"
	"time"

	"github.com/pires/go-proxyproto"
)

func main() {
	server := http.Server{
		Addr: ":8080",
	}

	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		panic(err)
	}

	proxyListener := &proxyproto.Listener{
		Listener:          ln,
		ReadHeaderTimeout: 10 * time.Second,
	}
	defer proxyListener.Close()

	server.Serve(proxyListener)
}
```

### TLS

When combining the PROXY protocol with TLS, the only real decision is the order
in which you wrap the listener, and it depends on where the upstream puts the
PROXY header relative to the TLS handshake.

**Header in cleartext, before the handshake** — the common case (e.g. AWS NLB
with proxy protocol v2, or HAProxy `send-proxy` in front of a TLS backend).
proxyproto must read the header first, so it goes **inside** the TLS listener:

```go
l, _ := net.Listen("tcp", addr)
// proxyproto INNER, tls OUTER
listener := tls.NewListener(&proxyproto.Listener{Listener: l}, tlsConfig)
```

**Header inside the TLS session, after the handshake** — only when you control
the upstream and it deliberately sends the header post-handshake. TLS must be
decrypted first, so proxyproto goes **outside** the TLS listener:

```go
l, _ := net.Listen("tcp", addr)
// tls INNER, proxyproto OUTER
listener := &proxyproto.Listener{Listener: tls.NewListener(l, tlsConfig)}
```

In both cases `conn.RemoteAddr()` returns the real client carried by the PROXY
header. Runnable code lives in [`examples/tlsserver`](examples/tlsserver) and
[`examples/tlsclient`](examples/tlsclient); the API examples
[`ExampleListener_tls`](https://pkg.go.dev/github.com/pires/go-proxyproto#example-Listener-Tls)
and
[`ExampleListener_tlsHeaderInsideTLS`](https://pkg.go.dev/github.com/pires/go-proxyproto#example-Listener-TlsHeaderInsideTLS)
show both orderings, and both are covered by tests (`Test_TLSServerHeaderBeforeTLS`,
`Test_TLSServerHeaderInsideTLS`).

## Special notes

### AWS

AWS Network Load Balancer (NLB) does not push the PPV2 header until the client starts sending the data. This is a problem if your server speaks first. e.g. SMTP, FTP, SSH etc.

By default, NLB target group attribute `proxy_protocol_v2.client_to_server.header_placement` has the value `on_first_ack_with_payload`. You need to contact AWS support to change it to `on_first_ack`, instead.

Just to be clear, you need this fix only if your server is designed to speak first.
