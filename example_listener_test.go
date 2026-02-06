package proxyproto_test

import (
	"net"
	"time"

	"github.com/pires/go-proxyproto"
)

// proxyV1Line is a minimal PROXY protocol v1 header for examples.
const proxyV1Line = "PROXY TCP4 192.168.1.1 192.168.1.2 12345 443\r\n"

func ExampleListener_default() {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	pl := &proxyproto.Listener{Listener: l}
	defer func() { _ = pl.Close() }()

	go func() {
		c, _ := net.Dial("tcp", pl.Addr().String())
		if c != nil {
			_, _ = c.Write([]byte("x"))
			_ = c.Close()
		}
	}()

	conn, _ := pl.Accept()
	if conn != nil {
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		_ = conn.Close()
	}
	// Output:
}

func ExampleListener_readHeaderTimeout() {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	pl := &proxyproto.Listener{
		Listener:          l,
		ReadHeaderTimeout: 2 * time.Second,
	}
	defer func() { _ = pl.Close() }()

	go func() {
		c, _ := net.Dial("tcp", pl.Addr().String())
		if c != nil {
			_, _ = c.Write([]byte("a"))
			_ = c.Close()
		}
	}()

	conn, _ := pl.Accept()
	if conn != nil {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		_ = conn.Close()
	}
	// Output:
}

func ExampleListener_readBufferSize() {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	pl := &proxyproto.Listener{
		Listener:       l,
		ReadBufferSize: 4096,
	}
	defer func() { _ = pl.Close() }()

	go func() {
		c, _ := net.Dial("tcp", pl.Addr().String())
		if c != nil {
			_, _ = c.Write([]byte("b"))
			_ = c.Close()
		}
	}()

	conn, _ := pl.Accept()
	if conn != nil {
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		_ = conn.Close()
	}
	// Output:
}

func ExampleListener_policyRequire() {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	pl := &proxyproto.Listener{
		Listener: l,
		Policy:   func(net.Addr) (proxyproto.Policy, error) { return proxyproto.REQUIRE, nil },
	}
	defer func() { _ = pl.Close() }()

	go func() {
		c, _ := net.Dial("tcp", pl.Addr().String())
		if c != nil {
			_, _ = c.Write([]byte(proxyV1Line))
			_, _ = c.Write([]byte("p"))
			_ = c.Close()
		}
	}()

	conn, _ := pl.Accept()
	if conn != nil {
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		_ = conn.Close()
	}
	// Output:
}

func ExampleListener_validateHeader() {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	pl := &proxyproto.Listener{
		Listener:       l,
		ValidateHeader: func(*proxyproto.Header) error { return nil },
	}
	defer func() { _ = pl.Close() }()

	go func() {
		c, _ := net.Dial("tcp", pl.Addr().String())
		if c != nil {
			_, _ = c.Write([]byte(proxyV1Line))
			_, _ = c.Write([]byte("v"))
			_ = c.Close()
		}
	}()

	conn, _ := pl.Accept()
	if conn != nil {
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		_ = conn.Close()
	}
	// Output:
}
