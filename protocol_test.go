// This file was shamefully stolen from github.com/armon/go-proxyproto.
// It has been heavily edited to conform to this lib.
//
// Thanks @armon
package proxyproto

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"testing"
	"time"
)

func TestPassthrough(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{Listener: l}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		conn.Write([]byte("ping"))
		recv := make([]byte, 4)
		_, err = conn.Read(recv)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !bytes.Equal(recv, []byte("pong")) {
			t.Fatalf("bad: %v", recv)
		}
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}
}

// TestRequiredWithReadHeaderTimeout will iterate through 3 different timeouts to see
// whether using a REQUIRE policy for a listener would cause an error if the timeout
// is triggerred without a proxy protocol header being defined.
func TestRequiredWithReadHeaderTimeout(t *testing.T) {
	for _, duration := range []int{100, 200, 400} {
		t.Run(fmt.Sprint(duration), func(t *testing.T) {
			start := time.Now()

			l, err := net.Listen("tcp", "127.0.0.1:0")

			if err != nil {
				t.Fatalf("err: %v", err)
			}

			pl := &Listener{
				Listener:          l,
				ReadHeaderTimeout: time.Millisecond * time.Duration(duration),
				Policy: func(upstream net.Addr) (Policy, error) {
					return REQUIRE, nil
				},
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			go func() {
				conn, err := net.Dial("tcp", pl.Addr().String())
				if err != nil {
					t.Fatalf("err: %v", err)
				}
				defer conn.Close()

				<-ctx.Done()
			}()

			conn, err := pl.Accept()
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			defer conn.Close()

			// Read blocks forever if there is no ReadHeaderTimeout and the policy is not REQUIRE
			recv := make([]byte, 4)
			_, err = conn.Read(recv)

			if err != nil && !errors.Is(err, ErrNoProxyProtocol) && time.Since(start)-pl.ReadHeaderTimeout > 10*time.Millisecond {
				t.Fatal("proxy proto should not be found and time should be close to read timeout")
			}
		})
	}
}

// TestUseWithReadHeaderTimeout will iterate through 3 different timeouts to see
// whether using a USE policy for a listener would not cause an error if the timeout
// is triggerred without a proxy protocol header being defined.
func TestUseWithReadHeaderTimeout(t *testing.T) {
	for _, duration := range []int{100, 200, 400} {
		t.Run(fmt.Sprint(duration), func(t *testing.T) {
			start := time.Now()

			l, err := net.Listen("tcp", "127.0.0.1:0")

			if err != nil {
				t.Fatalf("err: %v", err)
			}

			pl := &Listener{
				Listener:          l,
				ReadHeaderTimeout: time.Millisecond * time.Duration(duration),
				Policy: func(upstream net.Addr) (Policy, error) {
					return USE, nil
				},
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			go func() {
				conn, err := net.Dial("tcp", pl.Addr().String())
				if err != nil {
					t.Fatalf("err: %v", err)
				}
				defer conn.Close()

				<-ctx.Done()
			}()

			conn, err := pl.Accept()
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			defer conn.Close()

			// 2 times the ReadHeaderTimeout because the first timeout
			// should occur (the one set on the listener) and allow for the second to follow up
			conn.SetDeadline(time.Now().Add(pl.ReadHeaderTimeout * 2))

			// Read blocks forever if there is no ReadHeaderTimeout
			recv := make([]byte, 4)
			_, err = conn.Read(recv)

			if err != nil && !errors.Is(err, ErrNoProxyProtocol) && (time.Since(start)-(pl.ReadHeaderTimeout*2)) > 10*time.Millisecond {
				t.Fatal("proxy proto should not be found and time should be close to read timeout")
			}
		})
	}
}

func TestReadHeaderTimeoutIsReset(t *testing.T) {
	const timeout = time.Millisecond * 250

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{
		Listener:          l,
		ReadHeaderTimeout: timeout,
	}

	header := &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: TCPv4,
		SourceAddr: &net.TCPAddr{
			IP:   net.ParseIP("10.1.1.1"),
			Port: 1000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP("20.2.2.2"),
			Port: 2000,
		},
	}
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Write out the header!
		header.WriteTo(conn)

		// Sleep here longer than the configured timeout.
		time.Sleep(timeout * 2)

		conn.Write([]byte("ping"))
		recv := make([]byte, 4)
		_, err = conn.Read(recv)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !bytes.Equal(recv, []byte("pong")) {
			t.Fatalf("bad: %v", recv)
		}
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	// Set our deadlines higher than our ReadHeaderTimeout
	conn.SetReadDeadline(time.Now().Add(timeout * 3))
	conn.SetWriteDeadline(time.Now().Add(timeout * 3))

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the remote addr
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if addr.IP.String() != "10.1.1.1" {
		t.Fatalf("bad: %v", addr)
	}
	if addr.Port != 1000 {
		t.Fatalf("bad: %v", addr)
	}

	h := conn.(*Conn).ProxyHeader()
	if !h.EqualsTo(header) {
		t.Errorf("bad: %v", h)
	}
}

// TestReadHeaderTimeoutIsEmpty ensures the default is set if it is empty.
// Because the default is 200ms and we wait longer than that to send a message,
// we expect the actual address and port to be returned,
// rather than the ProxyHeader we defined.
func TestReadHeaderTimeoutIsEmpty(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{
		Listener: l,
	}

	header := &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: TCPv4,
		SourceAddr: &net.TCPAddr{
			IP:   net.ParseIP("10.1.1.1"),
			Port: 1000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP("20.2.2.2"),
			Port: 2000,
		},
	}
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Sleep here longer than the configured timeout.
		time.Sleep(250 * time.Millisecond)

		// Write out the header!
		header.WriteTo(conn)

		conn.Write([]byte("ping"))
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the remote addr
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if addr.IP.String() == "10.1.1.1" {
		t.Fatalf("bad: %v", addr)
	}
	if addr.Port == 1000 {
		t.Fatalf("bad: %v", addr)
	}
}

// TestReadHeaderTimeoutIsNegative does the same as above except
// with a negative timeout. Therefore, we expect the right ProxyHeader
// to be returned.
func TestReadHeaderTimeoutIsNegative(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{
		Listener:          l,
		ReadHeaderTimeout: -1,
	}

	header := &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: TCPv4,
		SourceAddr: &net.TCPAddr{
			IP:   net.ParseIP("10.1.1.1"),
			Port: 1000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP("20.2.2.2"),
			Port: 2000,
		},
	}
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Sleep here longer than the configured timeout.
		time.Sleep(250 * time.Millisecond)

		// Write out the header!
		header.WriteTo(conn)

		conn.Write([]byte("ping"))
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the remote addr
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if addr.IP.String() != "10.1.1.1" {
		t.Fatalf("bad: %v", addr)
	}
	if addr.Port != 1000 {
		t.Fatalf("bad: %v", addr)
	}
}

func TestParse_ipv4(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{Listener: l}

	header := &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: TCPv4,
		SourceAddr: &net.TCPAddr{
			IP:   net.ParseIP("10.1.1.1"),
			Port: 1000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP("20.2.2.2"),
			Port: 2000,
		},
	}
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Write out the header!
		header.WriteTo(conn)

		conn.Write([]byte("ping"))
		recv := make([]byte, 4)
		_, err = conn.Read(recv)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !bytes.Equal(recv, []byte("pong")) {
			t.Fatalf("bad: %v", recv)
		}
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the remote addr
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if addr.IP.String() != "10.1.1.1" {
		t.Fatalf("bad: %v", addr)
	}
	if addr.Port != 1000 {
		t.Fatalf("bad: %v", addr)
	}

	h := conn.(*Conn).ProxyHeader()
	if !h.EqualsTo(header) {
		t.Errorf("bad: %v", h)
	}
}

func TestParse_ipv6(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{Listener: l}

	header := &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: TCPv6,
		SourceAddr: &net.TCPAddr{
			IP:   net.ParseIP("ffff::ffff"),
			Port: 1000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP("ffff::ffff"),
			Port: 2000,
		},
	}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Write out the header!
		header.WriteTo(conn)

		conn.Write([]byte("ping"))
		recv := make([]byte, 4)
		_, err = conn.Read(recv)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !bytes.Equal(recv, []byte("pong")) {
			t.Fatalf("bad: %v", recv)
		}
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the remote addr
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if addr.IP.String() != "ffff::ffff" {
		t.Fatalf("bad: %v", addr)
	}
	if addr.Port != 1000 {
		t.Fatalf("bad: %v", addr)
	}

	h := conn.(*Conn).ProxyHeader()
	if !h.EqualsTo(header) {
		t.Errorf("bad: %v", h)
	}
}

func TestAcceptReturnsErrorWhenPolicyFuncErrors(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	expectedErr := fmt.Errorf("failure")
	policyFunc := func(upstream net.Addr) (Policy, error) { return USE, expectedErr }

	pl := &Listener{Listener: l, Policy: policyFunc}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()
	}()

	conn, err := pl.Accept()
	if err != expectedErr {
		t.Fatalf("Expected error %v, got %v", expectedErr, err)
	}

	if conn != nil {
		t.Fatalf("Expected no connection, got %v", conn)
	}
}

func TestReadingIsRefusedWhenProxyHeaderRequiredButMissing(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	policyFunc := func(upstream net.Addr) (Policy, error) { return REQUIRE, nil }

	pl := &Listener{Listener: l, Policy: policyFunc}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()
		conn.Write([]byte("ping"))
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != ErrNoProxyProtocol {
		t.Fatalf("Expected error %v, received %v", ErrNoProxyProtocol, err)
	}
}

func TestReadingIsRefusedWhenProxyHeaderPresentButNotAllowed(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	policyFunc := func(upstream net.Addr) (Policy, error) { return REJECT, nil }

	pl := &Listener{Listener: l, Policy: policyFunc}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()
		header := &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: TCPv4,
			SourceAddr: &net.TCPAddr{
				IP:   net.ParseIP("10.1.1.1"),
				Port: 1000,
			},
			DestinationAddr: &net.TCPAddr{
				IP:   net.ParseIP("20.2.2.2"),
				Port: 2000,
			},
		}
		header.WriteTo(conn)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != ErrSuperfluousProxyHeader {
		t.Fatalf("Expected error %v, received %v", ErrSuperfluousProxyHeader, err)
	}
}
func TestIgnorePolicyIgnoresIpFromProxyHeader(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	policyFunc := func(upstream net.Addr) (Policy, error) { return IGNORE, nil }

	pl := &Listener{Listener: l, Policy: policyFunc}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Write out the header!
		header := &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: TCPv4,
			SourceAddr: &net.TCPAddr{
				IP:   net.ParseIP("10.1.1.1"),
				Port: 1000,
			},
			DestinationAddr: &net.TCPAddr{
				IP:   net.ParseIP("20.2.2.2"),
				Port: 2000,
			},
		}
		header.WriteTo(conn)

		conn.Write([]byte("ping"))
		recv := make([]byte, 4)
		_, err = conn.Read(recv)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !bytes.Equal(recv, []byte("pong")) {
			t.Fatalf("bad: %v", recv)
		}
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the remote addr
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if addr.IP.String() != "127.0.0.1" {
		t.Fatalf("bad: %v", addr)
	}
}

func Test_AllOptionsAreRecognized(t *testing.T) {
	recognizedOpt1 := false
	opt1 := func(c *Conn) {
		recognizedOpt1 = true
	}

	recognizedOpt2 := false
	opt2 := func(c *Conn) {
		recognizedOpt2 = true
	}

	server, client := net.Pipe()
	defer func() {
		client.Close()
	}()

	c := NewConn(server, opt1, opt2)
	if !recognizedOpt1 {
		t.Error("Expected option 1 recognized")
	}

	if !recognizedOpt2 {
		t.Error("Expected option 2 recognized")
	}

	c.Close()
}

func TestReadingIsRefusedOnErrorWhenRemoteAddrRequestedFirst(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	policyFunc := func(upstream net.Addr) (Policy, error) { return REQUIRE, nil }

	pl := &Listener{Listener: l, Policy: policyFunc}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()
		conn.Write([]byte("ping"))
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	_ = conn.RemoteAddr()
	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != ErrNoProxyProtocol {
		t.Fatalf("Expected error %v, received %v", ErrNoProxyProtocol, err)
	}
}

func TestReadingIsRefusedOnErrorWhenLocalAddrRequestedFirst(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	policyFunc := func(upstream net.Addr) (Policy, error) { return REQUIRE, nil }

	pl := &Listener{Listener: l, Policy: policyFunc}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()
		conn.Write([]byte("ping"))
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	_ = conn.LocalAddr()
	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != ErrNoProxyProtocol {
		t.Fatalf("Expected error %v, received %v", ErrNoProxyProtocol, err)
	}
}

func Test_ConnectionCasts(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	policyFunc := func(upstream net.Addr) (Policy, error) { return REQUIRE, nil }

	pl := &Listener{Listener: l, Policy: policyFunc}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()
		conn.Write([]byte("ping"))
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	proxyprotoConn := conn.(*Conn)
	_, ok := proxyprotoConn.TCPConn()
	if !ok {
		t.Fatal("err: should be a tcp connection")
	}
	_, ok = proxyprotoConn.UDPConn()
	if ok {
		t.Fatal("err: should be a tcp connection not udp")
	}
	_, ok = proxyprotoConn.UnixConn()
	if ok {
		t.Fatal("err: should be a tcp connection not unix")
	}
	_, ok = proxyprotoConn.Raw().(*net.TCPConn)
	if !ok {
		t.Fatal("err: should be a tcp connection")
	}
}

func Test_ConnectionErrorsWhenHeaderValidationFails(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	validationError := fmt.Errorf("failed to validate")
	pl := &Listener{Listener: l, ValidateHeader: func(*Header) error { return validationError }}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Write out the header!
		header := &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: TCPv4,
			SourceAddr: &net.TCPAddr{
				IP:   net.ParseIP("10.1.1.1"),
				Port: 1000,
			},
			DestinationAddr: &net.TCPAddr{
				IP:   net.ParseIP("20.2.2.2"),
				Port: 2000,
			},
		}
		header.WriteTo(conn)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != validationError {
		t.Fatalf("expected validation error, got %v", err)
	}
}

type TestTLSServer struct {
	Listener net.Listener

	// TLS is the optional TLS configuration, populated with a new config
	// after TLS is started. If set on an unstarted server before StartTLS
	// is called, existing fields are copied into the new config.
	TLS             *tls.Config
	TLSClientConfig *tls.Config

	// certificate is a parsed version of the TLS config certificate, if present.
	certificate *x509.Certificate
}

func (s *TestTLSServer) Addr() string {
	return s.Listener.Addr().String()
}

func (s *TestTLSServer) Close() {
	s.Listener.Close()
}

// based on net/http/httptest/Server.StartTLS
func NewTestTLSServer(l net.Listener) *TestTLSServer {
	s := &TestTLSServer{}

	cert, err := tls.X509KeyPair(LocalhostCert, LocalhostKey)
	if err != nil {
		panic(fmt.Sprintf("httptest: NewTLSServer: %v", err))
	}
	s.TLS = new(tls.Config)
	if len(s.TLS.Certificates) == 0 {
		s.TLS.Certificates = []tls.Certificate{cert}
	}
	s.certificate, err = x509.ParseCertificate(s.TLS.Certificates[0].Certificate[0])
	if err != nil {
		panic(fmt.Sprintf("NewTestTLSServer: %v", err))
	}
	certpool := x509.NewCertPool()
	certpool.AddCert(s.certificate)
	s.TLSClientConfig = &tls.Config{
		RootCAs: certpool,
	}
	s.Listener = tls.NewListener(l, s.TLS)

	return s
}

func Test_TLSServer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	s := NewTestTLSServer(l)
	s.Listener = &Listener{
		Listener: s.Listener,
		Policy: func(upstream net.Addr) (Policy, error) {
			return REQUIRE, nil
		},
	}
	defer s.Close()

	go func() {
		conn, err := tls.Dial("tcp", s.Addr(), s.TLSClientConfig)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Write out the header!
		header := &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: TCPv4,
			SourceAddr: &net.TCPAddr{
				IP:   net.ParseIP("10.1.1.1"),
				Port: 1000,
			},
			DestinationAddr: &net.TCPAddr{
				IP:   net.ParseIP("20.2.2.2"),
				Port: 2000,
			},
		}
		header.WriteTo(conn)

		conn.Write([]byte("test"))
	}()

	conn, err := s.Listener.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 1024)
	n, err := conn.Read(recv)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if string(recv[:n]) != "test" {
		t.Fatalf("expected \"test\", got \"%s\" %v", recv[:n], recv[:n])
	}
}

func Test_MisconfiguredTLSServerRespondsWithUnderlyingError(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	s := NewTestTLSServer(l)
	s.Listener = &Listener{
		Listener: s.Listener,
		Policy: func(upstream net.Addr) (Policy, error) {
			return REQUIRE, nil
		},
	}
	defer s.Close()

	go func() {
		// this is not a valid TLS connection, we are
		// connecting to the TLS endpoint via plain TCP.
		//
		// it's an example of a configuration error:
		// client: HTTP  -> PROXY
		// server: PROXY -> TLS -> HTTP
		//
		// we want to bubble up the underlying error,
		// in this case a tls handshake error, instead
		// of responding with a non-descript
		// > "Proxy protocol signature not present".

		conn, err := net.Dial("tcp", s.Addr())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Write out the header!
		header := &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: TCPv4,
			SourceAddr: &net.TCPAddr{
				IP:   net.ParseIP("10.1.1.1"),
				Port: 1000,
			},
			DestinationAddr: &net.TCPAddr{
				IP:   net.ParseIP("20.2.2.2"),
				Port: 2000,
			},
		}
		header.WriteTo(conn)

		conn.Write([]byte("GET /foo/bar HTTP/1.1"))
	}()

	conn, err := s.Listener.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 1024)
	_, err = conn.Read(recv)
	if err.Error() != "tls: first record does not look like a TLS handshake" {
		t.Fatalf("expected tls handshake error, got %s", err)
	}
}

type testConn struct {
	readFromCalledWith io.Reader
	reads              int
	net.Conn           // nil; crash on any unexpected use
}

func (c *testConn) ReadFrom(r io.Reader) (int64, error) {
	c.readFromCalledWith = r
	b, err := ioutil.ReadAll(r)
	return int64(len(b)), err
}
func (c *testConn) Write(p []byte) (int, error) {
	return len(p), nil
}
func (c *testConn) Read(p []byte) (int, error) {
	if c.reads == 0 {
		return 0, io.EOF
	}
	c.reads--
	return 1, nil
}

func TestCopyToWrappedConnection(t *testing.T) {
	innerConn := &testConn{}
	wrappedConn := NewConn(innerConn)
	dummySrc := &testConn{reads: 1}

	io.Copy(wrappedConn, dummySrc)
	if innerConn.readFromCalledWith != dummySrc {
		t.Error("Expected io.Copy to delegate to ReadFrom function of inner destination connection")
	}
}

func TestCopyFromWrappedConnection(t *testing.T) {
	wrappedConn := NewConn(&testConn{reads: 1})
	dummyDst := &testConn{}

	io.Copy(dummyDst, wrappedConn)
	if dummyDst.readFromCalledWith != wrappedConn.conn {
		t.Errorf("Expected io.Copy to pass inner source connection to ReadFrom method of destination")
	}
}

func TestCopyFromWrappedConnectionToWrappedConnection(t *testing.T) {
	innerConn1 := &testConn{reads: 1}
	wrappedConn1 := NewConn(innerConn1)
	innerConn2 := &testConn{}
	wrappedConn2 := NewConn(innerConn2)

	io.Copy(wrappedConn1, wrappedConn2)
	if innerConn1.readFromCalledWith != innerConn2 {
		t.Errorf("Expected io.Copy to pass inner source connection to ReadFrom of inner destination connection")
	}
}

func benchmarkTCPProxy(size int, b *testing.B) {
	//create and start the echo backend
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("err: %v", err)
	}
	defer backend.Close()
	go func() {
		for {
			conn, err := backend.Accept()
			if err != nil {
				break
			}
			_, err = io.Copy(conn, conn)
			conn.Close()
			if err != nil {
				b.Fatalf("Failed to read entire payload: %v", err)
			}
		}
	}()

	//start the proxyprotocol enabled tcp proxy
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("err: %v", err)
	}
	defer l.Close()
	pl := &Listener{Listener: l}
	go func() {
		for {
			conn, err := pl.Accept()
			if err != nil {
				break
			}
			bConn, err := net.Dial("tcp", backend.Addr().String())
			if err != nil {
				b.Fatalf("failed to dial backend: %v", err)
			}
			go func() {
				_, err = io.Copy(bConn, conn)
				if err != nil {
					b.Fatalf("Failed to proxy incoming data to backend: %v", err)
				}
				bConn.(*net.TCPConn).CloseWrite()
			}()
			_, err = io.Copy(conn, bConn)
			if err != nil {
				b.Fatalf("Failed to proxy data from backend: %v", err)
			}
			conn.Close()
			bConn.Close()
		}
	}()

	data := make([]byte, size)

	header := &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: TCPv4,
		SourceAddr: &net.TCPAddr{
			IP:   net.ParseIP("10.1.1.1"),
			Port: 1000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP("20.2.2.2"),
			Port: 2000,
		},
	}

	//now for the actual benchmark
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			b.Fatalf("err: %v", err)
		}
		// Write out the header!
		header.WriteTo(conn)
		//send data
		go func() {
			_, err = conn.Write(data)
			if err != nil {
				b.Fatalf("Failed to write data: %v", err)
			}
			conn.(*net.TCPConn).CloseWrite()

		}()
		//receive data
		n, err := io.Copy(ioutil.Discard, conn)
		if n != int64(len(data)) {
			b.Fatalf("Expected to receive %d bytes, got %d", len(data), n)
		}
		if err != nil {
			b.Fatalf("Failed to read data: %v", err)
		}
		conn.Close()
	}
}

func BenchmarkTCPProxy16KB(b *testing.B) {
	benchmarkTCPProxy(16*1024, b)
}
func BenchmarkTCPProxy32KB(b *testing.B) {
	benchmarkTCPProxy(32*1024, b)
}
func BenchmarkTCPProxy64KB(b *testing.B) {
	benchmarkTCPProxy(64*1024, b)
}
func BenchmarkTCPProxy128KB(b *testing.B) {
	benchmarkTCPProxy(128*1024, b)
}
func BenchmarkTCPProxy256KB(b *testing.B) {
	benchmarkTCPProxy(256*1024, b)
}
func BenchmarkTCPProxy512KB(b *testing.B) {
	benchmarkTCPProxy(512*1024, b)
}
func BenchmarkTCPProxy1024KB(b *testing.B) {
	benchmarkTCPProxy(1024*1024, b)
}
func BenchmarkTCPProxy2048KB(b *testing.B) {
	benchmarkTCPProxy(2048*1024, b)
}

// copied from src/net/http/internal/testcert.go

// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// LocalhostCert is a PEM-encoded TLS cert with SAN IPs
// "127.0.0.1" and "[::1]", expiring at Jan 29 16:00:00 2084 GMT.
// generated from src/crypto/tls:
// go run generate_cert.go  --rsa-bits 1024 --host 127.0.0.1,::1,example.com --ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
var LocalhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIICEzCCAXygAwIBAgIQMIMChMLGrR+QvmQvpwAU6zANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMCAXDTcwMDEwMTAwMDAwMFoYDzIwODQwMTI5MTYw
MDAwWjASMRAwDgYDVQQKEwdBY21lIENvMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB
iQKBgQDuLnQAI3mDgey3VBzWnB2L39JUU4txjeVE6myuDqkM/uGlfjb9SjY1bIw4
iA5sBBZzHi3z0h1YV8QPuxEbi4nW91IJm2gsvvZhIrCHS3l6afab4pZBl2+XsDul
rKBxKKtD1rGxlG4LjncdabFn9gvLZad2bSysqz/qTAUStTvqJQIDAQABo2gwZjAO
BgNVHQ8BAf8EBAMCAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUw
AwEB/zAuBgNVHREEJzAlggtleGFtcGxlLmNvbYcEfwAAAYcQAAAAAAAAAAAAAAAA
AAAAATANBgkqhkiG9w0BAQsFAAOBgQCEcetwO59EWk7WiJsG4x8SY+UIAA+flUI9
tyC4lNhbcF2Idq9greZwbYCqTTTr2XiRNSMLCOjKyI7ukPoPjo16ocHj+P3vZGfs
h1fIw3cSS2OolhloGw/XM6RWPWtPAlGykKLciQrBru5NAPvCMsb/I1DAceTiotQM
fblo6RBxUQ==
-----END CERTIFICATE-----`)

// LocalhostKey is the private key for localhostCert.
var LocalhostKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDuLnQAI3mDgey3VBzWnB2L39JUU4txjeVE6myuDqkM/uGlfjb9
SjY1bIw4iA5sBBZzHi3z0h1YV8QPuxEbi4nW91IJm2gsvvZhIrCHS3l6afab4pZB
l2+XsDulrKBxKKtD1rGxlG4LjncdabFn9gvLZad2bSysqz/qTAUStTvqJQIDAQAB
AoGAGRzwwir7XvBOAy5tM/uV6e+Zf6anZzus1s1Y1ClbjbE6HXbnWWF/wbZGOpet
3Zm4vD6MXc7jpTLryzTQIvVdfQbRc6+MUVeLKwZatTXtdZrhu+Jk7hx0nTPy8Jcb
uJqFk541aEw+mMogY/xEcfbWd6IOkp+4xqjlFLBEDytgbIECQQDvH/E6nk+hgN4H
qzzVtxxr397vWrjrIgPbJpQvBsafG7b0dA4AFjwVbFLmQcj2PprIMmPcQrooz8vp
jy4SHEg1AkEA/v13/5M47K9vCxmb8QeD/asydfsgS5TeuNi8DoUBEmiSJwma7FXY
fFUtxuvL7XvjwjN5B30pNEbc6Iuyt7y4MQJBAIt21su4b3sjXNueLKH85Q+phy2U
fQtuUE9txblTu14q3N7gHRZB4ZMhFYyDy8CKrN2cPg/Fvyt0Xlp/DoCzjA0CQQDU
y2ptGsuSmgUtWj3NM9xuwYPm+Z/F84K6+ARYiZ6PYj013sovGKUFfYAqVXVlxtIX
qyUBnu3X9ps8ZfjLZO7BAkEAlT4R5Yl6cGhaJQYZHOde3JEMhNRcVFMO8dJDaFeo
f9Oeos0UUothgiDktdQHxdNEwLjQf7lJJBzV+5OtwswCWA==
-----END RSA PRIVATE KEY-----`)
