package proxyproto_test

import (
	"fmt"
	"net"
	"time"

	"github.com/pires/go-proxyproto"
)

func ExampleNewConn_default() {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	go func() {
		_, _ = clientConn.Write([]byte(proxyV1Line))
		_, _ = clientConn.Write([]byte("x"))
		_ = clientConn.Close()
	}()

	// By default a connection must open with a PROXY header (DefaultPolicy is
	// REQUIRE): a headerless connection fails its first Read with
	// ErrNoProxyProtocol. Detection is bounded by DefaultReadHeaderTimeout, so
	// a silent client cannot block it forever. RemoteAddr then reports the
	// client address carried by the header.
	conn := proxyproto.NewConn(serverConn)
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		fmt.Println("read error:", err)
		return
	}
	fmt.Println(conn.RemoteAddr())
	// Output: 192.168.1.1:12345
}

func ExampleNewConn_disableReadHeaderTimeout() {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	go func() {
		_, _ = clientConn.Write([]byte(proxyV1Line))
		_, _ = clientConn.Write([]byte("d"))
		_ = clientConn.Close()
	}()

	// NewConn applies DefaultReadHeaderTimeout by default; pass
	// SetReadHeaderTimeout(0) to opt out and manage read deadlines yourself.
	conn := proxyproto.NewConn(serverConn, proxyproto.SetReadHeaderTimeout(0))
	buf := make([]byte, 1)
	_, _ = conn.Read(buf)
	// Output:
}

func ExampleNewConn_withBufferSize() {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	go func() {
		_, _ = clientConn.Write([]byte(proxyV1Line))
		_, _ = clientConn.Write([]byte("y"))
		_ = clientConn.Close()
	}()

	conn := proxyproto.NewConn(serverConn, proxyproto.WithBufferSize(4096))
	buf := make([]byte, 1)
	_, _ = conn.Read(buf)
	// Output:
}

func ExampleNewConn_withReadHeaderTimeout() {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	go func() {
		_, _ = clientConn.Write([]byte(proxyV1Line))
		_, _ = clientConn.Write([]byte("z"))
		_ = clientConn.Close()
	}()

	conn := proxyproto.NewConn(serverConn, proxyproto.SetReadHeaderTimeout(time.Second))
	buf := make([]byte, 1)
	_, _ = conn.Read(buf)
	// Output:
}

func ExampleNewConn_withPolicy() {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	go func() {
		_, _ = clientConn.Write([]byte(proxyV1Line))
		_, _ = clientConn.Write([]byte("p"))
		_ = clientConn.Close()
	}()

	conn := proxyproto.NewConn(serverConn, proxyproto.WithPolicy(proxyproto.REQUIRE))
	buf := make([]byte, 1)
	_, _ = conn.Read(buf)
	// Output:
}

func ExampleNewConn_combined() {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	go func() {
		_, _ = clientConn.Write([]byte(proxyV1Line))
		_, _ = clientConn.Write([]byte("c"))
		_ = clientConn.Close()
	}()

	conn := proxyproto.NewConn(serverConn,
		proxyproto.WithBufferSize(2048),
		proxyproto.SetReadHeaderTimeout(2*time.Second),
	)
	buf := make([]byte, 1)
	_, _ = conn.Read(buf)
	// Output:
}
