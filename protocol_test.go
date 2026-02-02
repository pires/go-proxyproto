// This file was shamefully stolen from github.com/armon/go-proxyproto.
// It has been heavily edited to conform to this lib.
//
// Thanks @armon
package proxyproto

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// testSourceIPv4Addr is a source IPv4 address used in tests.
const testSourceIPv4Addr string = "10.1.1.1"

// testDestinationIPv4Addr is the destination IPv4 address used in tests.
const testDestinationIPv4Addr string = "20.2.2.2"

// testLocalhostRandomPort is a localhost random port used in tests.
const testLocalhostRandomPort string = "127.0.0.1:0"

func TestPassthrough(t *testing.T) {
	l, err := net.Listen("tcp", testLocalhostRandomPort)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{Listener: l}

	cliResult := make(chan error)
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}
		t.Cleanup(func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("failed to close connection: %v", closeErr)
			}
		})

		if _, err := conn.Write([]byte("ping")); err != nil {
			cliResult <- err
			return
		}
		recv := make([]byte, 4)
		if _, err = conn.Read(recv); err != nil {
			cliResult <- err
			return
		}
		if !bytes.Equal(recv, []byte("pong")) {
			cliResult <- fmt.Errorf("bad: %v", recv)
			return
		}
		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})

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
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

// TestRequiredWithReadHeaderTimeout will iterate through 3 different timeouts to see
// whether using a REQUIRE policy for a listener would cause an error if the timeout
// is triggerred without a proxy protocol header being defined.
func TestRequiredWithReadHeaderTimeout(t *testing.T) {
	for _, duration := range []int{100, 200, 400} {
		t.Run(fmt.Sprint(duration), func(t *testing.T) {
			start := time.Now()

			l, err := net.Listen("tcp", testLocalhostRandomPort)
			if err != nil {
				t.Fatalf("err: %v", err)
			}

			pl := &Listener{
				Listener:          l,
				ReadHeaderTimeout: time.Millisecond * time.Duration(duration),
				Policy: func(_ net.Addr) (Policy, error) {
					return REQUIRE, nil
				},
			}

			cliResult := make(chan error)
			go func() {
				conn, err := net.Dial("tcp", pl.Addr().String())
				if err != nil {
					cliResult <- err
					return
				}
				t.Cleanup(func() {
					if closeErr := conn.Close(); closeErr != nil {
						t.Errorf("failed to close connection: %v", closeErr)
					}
				})

				close(cliResult)
			}()

			conn, err := pl.Accept()
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			t.Cleanup(func() {
				if closeErr := conn.Close(); closeErr != nil {
					t.Errorf("failed to close connection: %v", closeErr)
				}
			})

			// Read blocks forever if there is no ReadHeaderTimeout and the policy is not REQUIRE
			recv := make([]byte, 4)
			_, err = conn.Read(recv)

			if err != nil && !errors.Is(err, ErrNoProxyProtocol) && time.Since(start)-pl.ReadHeaderTimeout > 10*time.Millisecond {
				t.Fatal("proxy proto should not be found and time should be close to read timeout")
			}
			err = <-cliResult
			if err != nil {
				t.Fatalf("client error: %v", err)
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

			l, err := net.Listen("tcp", testLocalhostRandomPort)
			if err != nil {
				t.Fatalf("err: %v", err)
			}

			pl := &Listener{
				Listener:          l,
				ReadHeaderTimeout: time.Millisecond * time.Duration(duration),
				Policy: func(_ net.Addr) (Policy, error) {
					return USE, nil
				},
			}

			cliResult := make(chan error)
			go func() {
				conn, err := net.Dial("tcp", pl.Addr().String())
				if err != nil {
					cliResult <- err
					return
				}
				t.Cleanup(func() {
					if closeErr := conn.Close(); closeErr != nil {
						t.Errorf("failed to close connection: %v", closeErr)
					}
				})

				close(cliResult)
			}()

			conn, err := pl.Accept()
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			t.Cleanup(func() {
				if closeErr := conn.Close(); closeErr != nil {
					t.Errorf("failed to close connection: %v", closeErr)
				}
			})

			// 2 times the ReadHeaderTimeout because the first timeout
			// should occur (the one set on the listener) and allow for the second to follow up
			if err := conn.SetDeadline(time.Now().Add(pl.ReadHeaderTimeout * 2)); err != nil {
				t.Fatalf("err: %v", err)
			}

			// Read blocks forever if there is no ReadHeaderTimeout
			recv := make([]byte, 4)
			_, err = conn.Read(recv)

			if err != nil && !errors.Is(err, ErrNoProxyProtocol) && (time.Since(start)-(pl.ReadHeaderTimeout*2)) > 10*time.Millisecond {
				t.Fatal("proxy proto should not be found and time should be close to read timeout")
			}
			err = <-cliResult
			if err != nil {
				t.Fatalf("client error: %v", err)
			}
		})
	}
}

func TestNewConnSetReadHeaderTimeoutOption(t *testing.T) {
	conn, peer := net.Pipe()
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})
	t.Cleanup(func() {
		if closeErr := peer.Close(); closeErr != nil {
			t.Errorf("failed to close peer connection: %v", closeErr)
		}
	})

	// Ensure SetReadHeaderTimeout sets the connection-specific timeout.
	timeout := 150 * time.Millisecond
	proxyConn := NewConn(conn, SetReadHeaderTimeout(timeout))
	if proxyConn.readHeaderTimeout != timeout {
		t.Fatalf("expected readHeaderTimeout %v, got %v", timeout, proxyConn.readHeaderTimeout)
	}
}

func TestNewConnSetReadHeaderTimeoutIgnoresNegative(t *testing.T) {
	conn, peer := net.Pipe()
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})
	t.Cleanup(func() {
		if closeErr := peer.Close(); closeErr != nil {
			t.Errorf("failed to close peer connection: %v", closeErr)
		}
	})

	// Negative values should be ignored, leaving the timeout unset.
	proxyConn := NewConn(conn, SetReadHeaderTimeout(-1))
	if proxyConn.readHeaderTimeout != 0 {
		t.Fatalf("expected readHeaderTimeout to remain 0, got %v", proxyConn.readHeaderTimeout)
	}
}

func TestReadHeaderTimeoutRespectsEarlierDeadline(t *testing.T) {
	const (
		headerTimeout = 200 * time.Millisecond
		userTimeout   = 60 * time.Millisecond
		tolerance     = 100 * time.Millisecond
	)

	l, err := net.Listen("tcp", testLocalhostRandomPort)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{
		Listener:          l,
		ReadHeaderTimeout: headerTimeout,
		Policy: func(_ net.Addr) (Policy, error) {
			// Use REQUIRE so a timeout is surfaced as ErrNoProxyProtocol.
			return REQUIRE, nil
		},
	}

	type dialResult struct {
		conn net.Conn
		err  error
	}

	dialResultCh := make(chan dialResult, 1)
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		dialResultCh <- dialResult{conn: conn, err: err}
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})

	result := <-dialResultCh
	if result.err != nil {
		t.Fatalf("client error: %v", result.err)
	}
	t.Cleanup(func() {
		if closeErr := result.conn.Close(); closeErr != nil {
			t.Errorf("failed to close client connection: %v", closeErr)
		}
	})

	// Set a shorter user deadline than the readHeaderTimeout and do not send data.
	if err := conn.SetReadDeadline(time.Now().Add(userTimeout)); err != nil {
		t.Fatalf("err: %v", err)
	}

	start := time.Now()
	recv := make([]byte, 1)
	_, err = conn.Read(recv)
	elapsed := time.Since(start)

	// The read should honor the earlier user deadline instead of waiting
	// for the longer readHeaderTimeout.
	if !errors.Is(err, ErrNoProxyProtocol) {
		t.Fatalf("expected ErrNoProxyProtocol, got: %v", err)
	}
	if elapsed > userTimeout+tolerance {
		t.Fatalf("read exceeded user deadline: elapsed=%v timeout=%v", elapsed, userTimeout)
	}
}

func TestDeadlineSettersAfterHeaderProcessed(t *testing.T) {
	conn, peer := net.Pipe()
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})
	t.Cleanup(func() {
		if closeErr := peer.Close(); closeErr != nil {
			t.Errorf("failed to close peer connection: %v", closeErr)
		}
	})

	proxyConn := NewConn(conn)

	// Ensure header processing completes by sending a non-PROXY byte
	// and reading it through the proxy connection.
	go func() {
		if _, err := peer.Write([]byte("x")); err != nil {
			t.Errorf("failed to write peer data: %v", err)
		}
	}()
	buf := make([]byte, 1)
	if _, err := proxyConn.Read(buf); err != nil {
		t.Fatalf("read failed: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	if err := proxyConn.SetDeadline(deadline); err != nil {
		t.Fatalf("unexpected SetDeadline error: %v", err)
	}
	if err := proxyConn.SetReadDeadline(deadline); err != nil {
		t.Fatalf("unexpected SetReadDeadline error: %v", err)
	}
	if err := proxyConn.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("unexpected SetWriteDeadline error: %v", err)
	}
}

func TestReadHeaderTimeoutIsReset(t *testing.T) {
	const timeout = time.Millisecond * 250

	l, err := net.Listen("tcp", testLocalhostRandomPort)
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
			IP:   net.ParseIP(testSourceIPv4Addr),
			Port: 1000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP(testDestinationIPv4Addr),
			Port: 2000,
		},
	}

	cliResult := make(chan error)
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}
		t.Cleanup(func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("failed to close connection: %v", closeErr)
			}
		})

		// Write out the header!
		if _, err := header.WriteTo(conn); err != nil {
			cliResult <- err
			return
		}

		// Sleep here longer than the configured timeout.
		time.Sleep(timeout * 2)

		if _, err := conn.Write([]byte("ping")); err != nil {
			cliResult <- err
			return
		}
		recv := make([]byte, 4)
		if _, err := conn.Read(recv); err != nil {
			cliResult <- err
			return
		}
		if !bytes.Equal(recv, []byte("pong")) {
			cliResult <- fmt.Errorf("bad: %v", recv)
			return
		}
		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})

	// Set our deadlines higher than our ReadHeaderTimeout
	if err := conn.SetReadDeadline(time.Now().Add(timeout * 3)); err != nil {
		t.Fatalf("err: %v", err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(timeout * 3)); err != nil {
		t.Fatalf("err: %v", err)
	}

	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != nil {
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
	if addr.IP.String() != testSourceIPv4Addr {
		t.Fatalf("bad: %v", addr)
	}
	if addr.Port != 1000 {
		t.Fatalf("bad: %v", addr)
	}

	h := conn.(*Conn).ProxyHeader()
	if !h.EqualsTo(header) {
		t.Errorf("bad: %v", h)
	}
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

// TestReadHeaderTimeoutIsEmpty ensures the default is set if it is empty.
// The default is 10s, but we delay sending a message, so use 200ms in this test.
// We expect the actual address and port to be returned,
// rather than the ProxyHeader we defined.
func TestReadHeaderTimeoutIsEmpty(t *testing.T) {
	DefaultReadHeaderTimeout = 200 * time.Millisecond

	l, err := net.Listen("tcp", testLocalhostRandomPort)
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
			IP:   net.ParseIP(testSourceIPv4Addr),
			Port: 1000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP(testDestinationIPv4Addr),
			Port: 2000,
		},
	}

	cliResult := make(chan error)
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}
		t.Cleanup(func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("failed to close connection: %v", closeErr)
			}
		})

		// Sleep here longer than the configured timeout.
		time.Sleep(250 * time.Millisecond)

		// Write out the header!
		if _, err := header.WriteTo(conn); err != nil {
			cliResult <- err
			return
		}

		if _, err := conn.Write([]byte("ping")); err != nil {
			cliResult <- err
			return
		}

		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})

	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the remote addr
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if addr.IP.String() == testSourceIPv4Addr {
		t.Fatalf("bad: %v", addr)
	}
	if addr.Port == 1000 {
		t.Fatalf("bad: %v", addr)
	}
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

// TestReadHeaderTimeoutIsNegative does the same as above except
// with a negative timeout. Therefore, we expect the right ProxyHeader
// to be returned.
func TestReadHeaderTimeoutIsNegative(t *testing.T) {
	l, err := net.Listen("tcp", testLocalhostRandomPort)
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
			IP:   net.ParseIP(testSourceIPv4Addr),
			Port: 1000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP(testDestinationIPv4Addr),
			Port: 2000,
		},
	}

	cliResult := make(chan error)
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}
		t.Cleanup(func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("failed to close connection: %v", closeErr)
			}
		})

		// Sleep here longer than the configured timeout.
		time.Sleep(250 * time.Millisecond)

		// Write out the header!
		if _, err := header.WriteTo(conn); err != nil {
			cliResult <- err
			return
		}

		if _, err := conn.Write([]byte("ping")); err != nil {
			cliResult <- err
			return
		}

		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})

	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the remote addr
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if addr.IP.String() != testSourceIPv4Addr {
		t.Fatalf("bad: %v", addr)
	}
	if addr.Port != 1000 {
		t.Fatalf("bad: %v", addr)
	}
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

func TestParse_ipv4(t *testing.T) {
	l, err := net.Listen("tcp", testLocalhostRandomPort)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{Listener: l}

	header := &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: TCPv4,
		SourceAddr: &net.TCPAddr{
			IP:   net.ParseIP(testSourceIPv4Addr),
			Port: 1000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP(testDestinationIPv4Addr),
			Port: 2000,
		},
	}

	cliResult := make(chan error)
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}
		t.Cleanup(func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("failed to close connection: %v", closeErr)
			}
		})

		// Write out the header!
		if _, err := header.WriteTo(conn); err != nil {
			cliResult <- err
			return
		}

		if _, err := conn.Write([]byte("ping")); err != nil {
			cliResult <- err
			return
		}

		recv := make([]byte, 4)
		if _, err = conn.Read(recv); err != nil {
			cliResult <- err
			return
		}
		if !bytes.Equal(recv, []byte("pong")) {
			cliResult <- fmt.Errorf("bad: %v", recv)
			return
		}
		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})

	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != nil {
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
	if addr.IP.String() != testSourceIPv4Addr {
		t.Fatalf("bad: %v", addr)
	}
	if addr.Port != 1000 {
		t.Fatalf("bad: %v", addr)
	}

	h := conn.(*Conn).ProxyHeader()
	if !h.EqualsTo(header) {
		t.Errorf("bad: %v", h)
	}
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

func TestParse_unixStream(t *testing.T) {
	socketDir := t.TempDir()
	socketPath := filepath.Join(socketDir, "proxy.sock")
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := l.Close(); closeErr != nil {
			t.Errorf("failed to close listener: %v", closeErr)
		}
	})

	pl := &Listener{Listener: l}

	header := &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: UnixStream,
		SourceAddr: &net.UnixAddr{
			Net:  "unix",
			Name: "source.sock",
		},
		DestinationAddr: &net.UnixAddr{
			Net:  "unix",
			Name: "dest.sock",
		},
	}

	cliResult := make(chan error)
	go func() {
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			cliResult <- err
			return
		}
		defer func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("failed to close connection: %v", closeErr)
			}
		}()

		// Write out the header!
		if _, err := header.WriteTo(conn); err != nil {
			cliResult <- err
			return
		}

		if _, err := conn.Write([]byte("ping")); err != nil {
			cliResult <- err
			return
		}

		recv := make([]byte, 4)
		if _, err = conn.Read(recv); err != nil {
			cliResult <- err
			return
		}
		if !bytes.Equal(recv, []byte("pong")) {
			cliResult <- fmt.Errorf("bad: %v", recv)
			return
		}

		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})

	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}

	addr := conn.RemoteAddr().(*net.UnixAddr)
	if addr.Name != header.SourceAddr.(*net.UnixAddr).Name {
		t.Fatalf("bad: %v", addr)
	}

	h := conn.(*Conn).ProxyHeader()
	if !h.EqualsTo(header) {
		t.Errorf("bad: %v", h)
	}

	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

func TestParse_unixDatagram(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Errorf("failed to close client: %v", closeErr)
		}
	})
	t.Cleanup(func() {
		if closeErr := server.Close(); closeErr != nil {
			t.Errorf("failed to close server: %v", closeErr)
		}
	})

	header := &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: UnixDatagram,
		SourceAddr: &net.UnixAddr{
			Net:  "unixgram",
			Name: "source.sock",
		},
		DestinationAddr: &net.UnixAddr{
			Net:  "unixgram",
			Name: "dest.sock",
		},
	}

	go func() {
		defer func() {
			if closeErr := client.Close(); closeErr != nil {
				t.Errorf("failed to close client: %v", closeErr)
			}
		}()
		if _, err := header.WriteTo(client); err != nil {
			t.Errorf("failed to write header: %v", err)
		}
		if _, err := client.Write([]byte("ping")); err != nil {
			t.Errorf("failed to write ping: %v", err)
		}
	}()

	conn := NewConn(server)
	recv := make([]byte, 4)
	if _, err := conn.Read(recv); err != nil {
		t.Fatalf("err: %v", err)
	}

	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	remoteAddr := conn.RemoteAddr().(*net.UnixAddr)
	if remoteAddr.Name != header.SourceAddr.(*net.UnixAddr).Name {
		t.Fatalf("bad: %v", remoteAddr)
	}

	localAddr := conn.LocalAddr().(*net.UnixAddr)
	if localAddr.Name != header.DestinationAddr.(*net.UnixAddr).Name {
		t.Fatalf("bad: %v", localAddr)
	}

	h := conn.ProxyHeader()
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

	cliResult := make(chan error)
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}
		t.Cleanup(func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("failed to close connection: %v", closeErr)
			}
		})

		// Write out the header!
		if _, err := header.WriteTo(conn); err != nil {
			cliResult <- err
			return
		}

		if _, err := conn.Write([]byte("ping")); err != nil {
			cliResult <- err
			return
		}

		recv := make([]byte, 4)
		if _, err = conn.Read(recv); err != nil {
			cliResult <- err
			return
		}
		if !bytes.Equal(recv, []byte("pong")) {
			cliResult <- fmt.Errorf("bad: %v", recv)
			return
		}
		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})

	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != nil {
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
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

func TestAcceptReturnsErrorWhenPolicyFuncErrors(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	expectedErr := fmt.Errorf("failure")
	policyFunc := func(_ net.Addr) (Policy, error) { return USE, expectedErr }

	pl := &Listener{Listener: l, Policy: policyFunc}

	cliResult := make(chan error)
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}
		t.Cleanup(func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("failed to close connection: %v", closeErr)
			}
		})
		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != expectedErr {
		t.Fatalf("Expected error %v, got %v", expectedErr, err)
	}

	if conn != nil {
		t.Fatalf("Expected no connection, got %v", conn)
	}
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

func TestPanicIfPolicyAndConnPolicySet(t *testing.T) {
	l, err := net.Listen("tcp", testLocalhostRandomPort)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	connPolicyFunc := func(_ ConnPolicyOptions) (Policy, error) { return USE, nil }
	policyFunc := func(_ net.Addr) (Policy, error) { return USE, nil }

	pl := &Listener{Listener: l, ConnPolicy: connPolicyFunc, Policy: policyFunc}

	cliResult := make(chan error)
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}
		t.Cleanup(func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("failed to close connection: %v", closeErr)
			}
		})

		close(cliResult)
	}()
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("accept did panic as expected with error, %v", r)
		}
	}()
	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("expected the accept to panic but did not and error is returned, got %v", err)
	}

	if conn != nil {
		t.Fatalf("expected the accept to panic but did not, got %v", conn)
	}
	t.Fatalf("expected the accept to panic but did not")
}

func TestAcceptReturnsErrorWhenConnPolicyFuncErrors(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	expectedErr := fmt.Errorf("failure")
	connPolicyFunc := func(_ ConnPolicyOptions) (Policy, error) { return USE, expectedErr }

	pl := &Listener{Listener: l, ConnPolicy: connPolicyFunc}

	cliResult := make(chan error)
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}
		t.Cleanup(func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("failed to close connection: %v", closeErr)
			}
		})

		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != expectedErr {
		t.Fatalf("Expected error %v, got %v", expectedErr, err)
	}

	if conn != nil {
		t.Fatalf("Expected no connection, got %v", conn)
	}
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

func TestReadingIsRefusedWhenProxyHeaderRequiredButMissing(t *testing.T) {
	l, err := net.Listen("tcp", testLocalhostRandomPort)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	policyFunc := func(_ net.Addr) (Policy, error) { return REQUIRE, nil }

	pl := &Listener{Listener: l, Policy: policyFunc}

	cliResult := make(chan error)
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}
		t.Cleanup(func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("failed to close connection: %v", closeErr)
			}
		})

		if _, err := conn.Write([]byte("ping")); err != nil {
			cliResult <- err
			return
		}

		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})

	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != ErrNoProxyProtocol {
		t.Fatalf("Expected error %v, received %v", ErrNoProxyProtocol, err)
	}
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

func TestReadingIsRefusedWhenProxyHeaderPresentButNotAllowed(t *testing.T) {
	l, err := net.Listen("tcp", testLocalhostRandomPort)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	policyFunc := func(_ net.Addr) (Policy, error) { return REJECT, nil }

	pl := &Listener{Listener: l, Policy: policyFunc}

	cliResult := make(chan error)
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}
		t.Cleanup(func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("failed to close connection: %v", closeErr)
			}
		})
		header := &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: TCPv4,
			SourceAddr: &net.TCPAddr{
				IP:   net.ParseIP(testSourceIPv4Addr),
				Port: 1000,
			},
			DestinationAddr: &net.TCPAddr{
				IP:   net.ParseIP(testDestinationIPv4Addr),
				Port: 2000,
			},
		}
		if _, err := header.WriteTo(conn); err != nil {
			cliResult <- err
			return
		}

		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})

	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != ErrSuperfluousProxyHeader {
		t.Fatalf("Expected error %v, received %v", ErrSuperfluousProxyHeader, err)
	}
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

func TestIgnorePolicyIgnoresIpFromProxyHeader(t *testing.T) {
	l, err := net.Listen("tcp", testLocalhostRandomPort)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	policyFunc := func(_ net.Addr) (Policy, error) { return IGNORE, nil }

	pl := &Listener{Listener: l, Policy: policyFunc}

	cliResult := make(chan error)
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}
		t.Cleanup(func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("failed to close connection: %v", closeErr)
			}
		})

		// Write out the header!
		header := &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: TCPv4,
			SourceAddr: &net.TCPAddr{
				IP:   net.ParseIP(testSourceIPv4Addr),
				Port: 1000,
			},
			DestinationAddr: &net.TCPAddr{
				IP:   net.ParseIP(testDestinationIPv4Addr),
				Port: 2000,
			},
		}
		if _, err := header.WriteTo(conn); err != nil {
			cliResult <- err
			return
		}

		if _, err := conn.Write([]byte("ping")); err != nil {
			cliResult <- err
			return
		}

		recv := make([]byte, 4)
		if _, err = conn.Read(recv); err != nil {
			cliResult <- err
			return
		}
		if !bytes.Equal(recv, []byte("pong")) {
			cliResult <- fmt.Errorf("bad: %v", recv)
			return
		}

		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})

	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != nil {
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
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

func Test_AllOptionsAreRecognized(t *testing.T) {
	recognizedOpt1 := false
	opt1 := func(_ *Conn) {
		recognizedOpt1 = true
	}

	recognizedOpt2 := false
	opt2 := func(_ *Conn) {
		recognizedOpt2 = true
	}

	server, client := net.Pipe()
	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})

	c := NewConn(server, opt1, opt2)
	if !recognizedOpt1 {
		t.Error("Expected option 1 recognized")
	}

	if !recognizedOpt2 {
		t.Error("Expected option 2 recognized")
	}

	t.Cleanup(func() {
		if closeErr := c.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})
}

func TestReadingIsRefusedOnErrorWhenRemoteAddrRequestedFirst(t *testing.T) {
	l, err := net.Listen("tcp", testLocalhostRandomPort)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	policyFunc := func(_ net.Addr) (Policy, error) { return REQUIRE, nil }

	pl := &Listener{Listener: l, Policy: policyFunc}

	cliResult := make(chan error)
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}
		t.Cleanup(func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("failed to close connection: %v", closeErr)
			}
		})

		if _, err := conn.Write([]byte("ping")); err != nil {
			cliResult <- err
			return
		}

		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})

	_ = conn.RemoteAddr()
	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != ErrNoProxyProtocol {
		t.Fatalf("Expected error %v, received %v", ErrNoProxyProtocol, err)
	}
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

func TestReadingIsRefusedOnErrorWhenLocalAddrRequestedFirst(t *testing.T) {
	l, err := net.Listen("tcp", testLocalhostRandomPort)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	policyFunc := func(_ net.Addr) (Policy, error) { return REQUIRE, nil }

	pl := &Listener{Listener: l, Policy: policyFunc}

	cliResult := make(chan error)
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}
		t.Cleanup(func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("failed to close connection: %v", closeErr)
			}
		})

		if _, err := conn.Write([]byte("ping")); err != nil {
			cliResult <- err
			return
		}

		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})

	_ = conn.LocalAddr()
	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != ErrNoProxyProtocol {
		t.Fatalf("Expected error %v, received %v", ErrNoProxyProtocol, err)
	}
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

func TestSkipProxyProtocolPolicy(t *testing.T) {
	l, err := net.Listen("tcp", testLocalhostRandomPort)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	connPolicyFunc := func(_ ConnPolicyOptions) (Policy, error) { return SKIP, nil }

	pl := &Listener{
		Listener:   l,
		ConnPolicy: connPolicyFunc,
	}

	cliResult := make(chan error)
	ping := []byte("ping")
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}
		t.Cleanup(func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("failed to close connection: %v", closeErr)
			}
		})

		if _, err := conn.Write(ping); err != nil {
			cliResult <- err
			return
		}

		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})

	_, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatal("err: should be a tcp connection")
	}
	_ = conn.LocalAddr()
	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != nil {
		t.Fatalf("Unexpected read error: %v", err)
	}

	if !bytes.Equal(ping, recv) {
		t.Fatalf("Unexpected %s data while expected %s", recv, ping)
	}

	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

func TestSkipProxyProtocolConnPolicy(t *testing.T) {
	l, err := net.Listen("tcp", testLocalhostRandomPort)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	policyFunc := func(_ net.Addr) (Policy, error) { return SKIP, nil }

	pl := &Listener{
		Listener: l,
		Policy:   policyFunc,
	}

	cliResult := make(chan error)
	ping := []byte("ping")
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}
		t.Cleanup(func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("failed to close connection: %v", closeErr)
			}
		})

		if _, err := conn.Write(ping); err != nil {
			cliResult <- err
			return
		}

		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})

	_, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatal("err: should be a tcp connection")
	}
	_ = conn.LocalAddr()
	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != nil {
		t.Fatalf("Unexpected read error: %v", err)
	}

	if !bytes.Equal(ping, recv) {
		t.Fatalf("Unexpected %s data while expected %s", recv, ping)
	}

	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

func TestLocalCommandUsesUnderlyingAddrs(t *testing.T) {
	l, err := net.Listen("tcp", testLocalhostRandomPort)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{Listener: l}

	header := &Header{
		Version:           2,
		Command:           LOCAL,
		TransportProtocol: UNSPEC,
	}

	cliResult := make(chan error)
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}

		// Write a LOCAL header with no address information.
		if _, err := header.WriteTo(conn); err != nil {
			cliResult <- err
			return
		}
		if _, err := conn.Write([]byte("ping")); err != nil {
			cliResult <- err
			return
		}

		// Close client side to avoid leaving the connection open.
		if err := conn.Close(); err != nil {
			cliResult <- err
			return
		}

		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})

	proxyConn := conn.(*Conn)
	// LOCAL should make LocalAddr/RemoteAddr fall back to underlying addresses.
	if proxyConn.LocalAddr().String() != proxyConn.Raw().LocalAddr().String() {
		t.Fatalf("LocalAddr should use underlying address for LOCAL command")
	}
	if proxyConn.RemoteAddr().String() != proxyConn.Raw().RemoteAddr().String() {
		t.Fatalf("RemoteAddr should use underlying address for LOCAL command")
	}

	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

func Test_ConnectionCasts(t *testing.T) {
	l, err := net.Listen("tcp", testLocalhostRandomPort)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	policyFunc := func(_ net.Addr) (Policy, error) { return REQUIRE, nil }

	pl := &Listener{Listener: l, Policy: policyFunc}

	cliResult := make(chan error)
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}
		t.Cleanup(func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("failed to close connection: %v", closeErr)
			}
		})

		if _, err := conn.Write([]byte("ping")); err != nil {
			cliResult <- err
			return
		}

		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})

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
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

func Test_ConnectionErrorsWhenHeaderValidationFails(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	validationError := fmt.Errorf("failed to validate")
	pl := &Listener{Listener: l, ValidateHeader: func(*Header) error { return validationError }}

	cliResult := make(chan error)
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}
		t.Cleanup(func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("failed to close connection: %v", closeErr)
			}
		})

		// Write out the header!
		header := &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: TCPv4,
			SourceAddr: &net.TCPAddr{
				IP:   net.ParseIP(testSourceIPv4Addr),
				Port: 1000,
			},
			DestinationAddr: &net.TCPAddr{
				IP:   net.ParseIP(testDestinationIPv4Addr),
				Port: 2000,
			},
		}
		if _, err := header.WriteTo(conn); err != nil {
			cliResult <- err
			return
		}

		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})

	recv := make([]byte, 4)
	if _, err = conn.Read(recv); err != validationError {
		t.Fatalf("expected validation error, got %v", err)
	}
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

func Test_ConnectionHandlesInvalidUpstreamError(t *testing.T) {
	l, err := net.Listen("tcp", "localhost:8080")
	if err != nil {
		t.Fatalf("error creating listener: %v", err)
	}

	var connectionCounter atomic.Int32

	newLn := &Listener{
		Listener: l,
		ConnPolicy: func(_ ConnPolicyOptions) (Policy, error) {
			// Return the invalid upstream error on the first call, the listener
			// should remain open and accepting.
			times := connectionCounter.Load()
			if times == 0 {
				connectionCounter.Store(times + 1)
				return REJECT, ErrInvalidUpstream
			}

			return REJECT, ErrNoProxyProtocol
		},
	}

	// Kick off the listener and return any error via the chanel.
	errCh := make(chan error)
	defer close(errCh)
	go func() {
		_, err := newLn.Accept()
		errCh <- err
	}()

	client := http.Client{Timeout: 200 * time.Millisecond}

	// Make two calls to trigger the listener's accept, the first should experience
	// the ErrInvalidUpstream and keep the listener open, the second should experience
	// a different error which will cause the listener to close.

	// First call should experience the ErrInvalidUpstream and keep the listener open.
	resp, err := client.Get("http://localhost:8080")
	if resp != nil {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("failed to close response body: %v", closeErr)
		}
	}
	if err != nil && !errors.Is(err, io.EOF) {
		t.Logf("first request failed as expected: %v", err)
	}

	// Ensure the ConnPolicy function was called at least once.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if connectionCounter.Load() >= 1 {
			break
		}
	}
	if connectionCounter.Load() < 1 {
		t.Fatalf("expected ConnPolicy to be called at least once")
	}

	// Wait a few seconds to ensure we didn't get anything back on our channel.
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("invalid upstream shouldn't return an error: %v", err)
		}
	case <-time.After(2 * time.Second):
		// No error returned (as expected, we're still listening though)
	}

	// Second call should experience a different error and cause the listener to close.
	resp, err = client.Get("http://localhost:8080")
	if resp != nil {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("failed to close response body: %v", closeErr)
		}
	}
	if err != nil && !errors.Is(err, io.EOF) {
		t.Logf("second request failed as expected: %v", err)
	}

	// Ensure the listener is closed.
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, ErrNoProxyProtocol) {
			t.Fatalf("unexpected error type: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for listener")
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

func (s *TestTLSServer) Close() error {
	return s.Listener.Close()
}

// based on net/http/httptest/Server.StartTLS.
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
		RootCAs:    certpool,
		MinVersion: tls.VersionTLS12,
	}
	s.Listener = tls.NewListener(l, s.TLS)

	return s
}

func Test_TLSServer(t *testing.T) {
	l, err := net.Listen("tcp", testLocalhostRandomPort)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	s := NewTestTLSServer(l)
	s.Listener = &Listener{
		Listener: s.Listener,
		Policy: func(_ net.Addr) (Policy, error) {
			return REQUIRE, nil
		},
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Errorf("failed to close TLS server: %v", err)
		}
	}()

	cliResult := make(chan error)
	go func() {
		conn, err := tls.Dial("tcp", s.Addr(), s.TLSClientConfig)
		if err != nil {
			cliResult <- err
			return
		}
		t.Cleanup(func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("failed to close connection: %v", closeErr)
			}
		})

		// Write out the header!
		header := &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: TCPv4,
			SourceAddr: &net.TCPAddr{
				IP:   net.ParseIP(testSourceIPv4Addr),
				Port: 1000,
			},
			DestinationAddr: &net.TCPAddr{
				IP:   net.ParseIP(testDestinationIPv4Addr),
				Port: 2000,
			},
		}
		if _, err := header.WriteTo(conn); err != nil {
			cliResult <- err
			return
		}

		if _, err := conn.Write([]byte("test")); err != nil {
			cliResult <- err
			return
		}

		close(cliResult)
	}()

	conn, err := s.Listener.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})

	recv := make([]byte, 1024)
	n, err := conn.Read(recv)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if string(recv[:n]) != "test" {
		t.Fatalf("expected \"test\", got \"%s\" %v", recv[:n], recv[:n])
	}
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

func Test_MisconfiguredTLSServerRespondsWithUnderlyingError(t *testing.T) {
	l, err := net.Listen("tcp", testLocalhostRandomPort)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	s := NewTestTLSServer(l)
	s.Listener = &Listener{
		Listener: s.Listener,
		Policy: func(_ net.Addr) (Policy, error) {
			return REQUIRE, nil
		},
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Errorf("failed to close TLS server: %v", err)
		}
	}()

	cliResult := make(chan error)
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
			cliResult <- err
			return
		}
		t.Cleanup(func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("failed to close connection: %v", closeErr)
			}
		})

		// Write out the header!
		header := &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: TCPv4,
			SourceAddr: &net.TCPAddr{
				IP:   net.ParseIP(testSourceIPv4Addr),
				Port: 1000,
			},
			DestinationAddr: &net.TCPAddr{
				IP:   net.ParseIP(testDestinationIPv4Addr),
				Port: 2000,
			},
		}
		if _, err := header.WriteTo(conn); err != nil {
			cliResult <- err
			return
		}

		if _, err := conn.Write([]byte("GET /foo/bar HTTP/1.1")); err != nil {
			cliResult <- err
			return
		}

		close(cliResult)
	}()

	conn, err := s.Listener.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})

	recv := make([]byte, 1024)
	if _, err = conn.Read(recv); err.Error() != "tls: first record does not look like a TLS handshake" {
		t.Fatalf("expected tls handshake error, got %s", err)
	}
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

type testConn struct {
	readFromCalledWith io.Reader
	reads              int
	net.Conn           // nil; crash on any unexpected use
}

type deadlineConn struct {
	deadline      time.Time
	readDeadline  time.Time
	writeDeadline time.Time
}

func (c *deadlineConn) Read(_ []byte) (int, error)  { return 0, io.EOF }
func (c *deadlineConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *deadlineConn) Close() error                { return nil }
func (c *deadlineConn) LocalAddr() net.Addr         { return dummyAddr("local") }
func (c *deadlineConn) RemoteAddr() net.Addr        { return dummyAddr("remote") }
func (c *deadlineConn) SetDeadline(t time.Time) error {
	c.deadline = t
	return nil
}
func (c *deadlineConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}
func (c *deadlineConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return nil
}

type noReadFromConn struct {
	written bytes.Buffer
}

func (c *noReadFromConn) Read(_ []byte) (int, error) { return 0, io.EOF }
func (c *noReadFromConn) Write(p []byte) (int, error) {
	return c.written.Write(p)
}
func (c *noReadFromConn) Close() error                { return nil }
func (c *noReadFromConn) LocalAddr() net.Addr         { return dummyAddr("local") }
func (c *noReadFromConn) RemoteAddr() net.Addr        { return dummyAddr("remote") }
func (c *noReadFromConn) SetDeadline(time.Time) error { return nil }
func (c *noReadFromConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *noReadFromConn) SetWriteDeadline(time.Time) error {
	return nil
}

type dummyAddr string

func (a dummyAddr) Network() string { return "dummy" }
func (a dummyAddr) String() string  { return string(a) }

func (c *testConn) ReadFrom(r io.Reader) (int64, error) {
	c.readFromCalledWith = r
	b, err := io.ReadAll(r)
	return int64(len(b)), err
}

func (c *testConn) Write(p []byte) (int, error) {
	return len(p), nil
}

func (c *testConn) Read(_ []byte) (int, error) {
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

	if _, err := io.Copy(wrappedConn, dummySrc); err != nil {
		t.Fatalf("err: %v", err)
	}
	if innerConn.readFromCalledWith != dummySrc {
		t.Error("Expected io.Copy to delegate to ReadFrom function of inner destination connection")
	}
}

func TestCopyFromWrappedConnection(t *testing.T) {
	wrappedConn := NewConn(&testConn{reads: 1})
	dummyDst := &testConn{}

	if _, err := io.Copy(dummyDst, wrappedConn); err != nil {
		t.Fatalf("err: %v", err)
	}
	if dummyDst.readFromCalledWith != wrappedConn.conn {
		t.Errorf("Expected io.Copy to pass inner source connection to ReadFrom method of destination")
	}
}

func TestCopyFromWrappedConnectionToWrappedConnection(t *testing.T) {
	innerConn1 := &testConn{reads: 1}
	wrappedConn1 := NewConn(innerConn1)
	innerConn2 := &testConn{}
	wrappedConn2 := NewConn(innerConn2)

	if _, err := io.Copy(wrappedConn1, wrappedConn2); err != nil {
		t.Fatalf("err: %v", err)
	}
	if innerConn1.readFromCalledWith != innerConn2 {
		t.Errorf("Expected io.Copy to pass inner source connection to ReadFrom of inner destination connection")
	}
}

func TestDeadlineWrappersDelegate(t *testing.T) {
	conn := &deadlineConn{}
	proxyConn := NewConn(conn)

	deadline := time.Now().Add(2 * time.Second)
	readDeadline := time.Now().Add(3 * time.Second)
	writeDeadline := time.Now().Add(4 * time.Second)

	// Ensure deadline setters pass through to the underlying connection.
	if err := proxyConn.SetDeadline(deadline); err != nil {
		t.Fatalf("unexpected SetDeadline error: %v", err)
	}
	if err := proxyConn.SetReadDeadline(readDeadline); err != nil {
		t.Fatalf("unexpected SetReadDeadline error: %v", err)
	}
	if err := proxyConn.SetWriteDeadline(writeDeadline); err != nil {
		t.Fatalf("unexpected SetWriteDeadline error: %v", err)
	}

	if !conn.deadline.Equal(deadline) {
		t.Fatalf("SetDeadline did not pass through value")
	}
	if !conn.readDeadline.Equal(readDeadline) {
		t.Fatalf("SetReadDeadline did not pass through value")
	}
	if !conn.writeDeadline.Equal(writeDeadline) {
		t.Fatalf("SetWriteDeadline did not pass through value")
	}
}

func TestReadFromFallbackCopiesToConn(t *testing.T) {
	conn := &noReadFromConn{}
	proxyConn := NewConn(conn)

	payload := []byte("payload")
	if _, err := proxyConn.ReadFrom(bytes.NewReader(payload)); err != nil {
		t.Fatalf("unexpected ReadFrom error: %v", err)
	}

	// When the inner connection does not implement io.ReaderFrom,
	// ReadFrom should fall back to io.Copy and write the payload.
	if !bytes.Equal(conn.written.Bytes(), payload) {
		t.Fatalf("unexpected write content: %q", conn.written.String())
	}
}

func TestWriteToDrainsBufferedData(t *testing.T) {
	l, err := net.Listen("tcp", testLocalhostRandomPort)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{Listener: l}

	header := &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: TCPv4,
		SourceAddr: &net.TCPAddr{
			IP:   net.ParseIP(testSourceIPv4Addr),
			Port: 1000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP(testDestinationIPv4Addr),
			Port: 2000,
		},
	}

	payload := []byte("ping")

	cliResult := make(chan error)
	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			cliResult <- err
			return
		}

		// Write the header followed by payload to populate the reader buffer.
		if _, err := header.WriteTo(conn); err != nil {
			cliResult <- err
			return
		}
		if _, err := conn.Write(payload); err != nil {
			cliResult <- err
			return
		}

		// Close the client so WriteTo's io.Copy completes.
		if err := conn.Close(); err != nil {
			cliResult <- err
			return
		}

		close(cliResult)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("failed to close connection: %v", closeErr)
		}
	})

	var out bytes.Buffer
	if _, err := conn.(*Conn).WriteTo(&out); err != nil {
		t.Fatalf("unexpected WriteTo error: %v", err)
	}
	if !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("unexpected WriteTo output: %q", out.String())
	}

	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

// chunkedConn wraps a net.Conn and limits reads to simulate TCP chunking.
type chunkedConn struct {
	net.Conn
	maxRead int
}

func (c *chunkedConn) Read(b []byte) (int, error) {
	if len(b) > c.maxRead {
		b = b[:c.maxRead]
	}
	return c.Conn.Read(b)
}

// TestConnReadTruncatesData demonstrates that Conn.Read() only returns
// buffered data when the initial TCP read is smaller than the payload.
func TestConnReadTruncatesData(t *testing.T) {
	const payloadSize = 400

	proxyHeader := []byte("PROXY TCP4 192.168.1.1 192.168.1.2 12345 443\r\n")
	payload := bytes.Repeat([]byte("X"), payloadSize)
	fullData := append(proxyHeader, payload...)

	serverConn, clientConn := net.Pipe()
	defer func() {
		serverCloseErr := serverConn.Close()
		clientCloseErr := clientConn.Close()
		if serverCloseErr != nil || clientCloseErr != nil {
			t.Errorf("failed to close connection: %v, %v", serverCloseErr, clientCloseErr)
		}
	}()

	go func() {
		_, _ = clientConn.Write(fullData)
	}()

	// Simulate TCP delivering only 256 bytes in first read
	chunked := &chunkedConn{Conn: serverConn, maxRead: 256}

	// Create a ProxyProto-wrapped connection
	conn := NewConn(chunked)
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))

	buf := make([]byte, 16384)
	n, _ := conn.Read(buf)

	t.Logf("Sent: %d bytes payload (after %d byte PROXY header)", payloadSize, len(proxyHeader))
	t.Logf("Read: %d bytes", n)

	if n < payloadSize {
		t.Errorf("BUG: Read returned %d bytes, expected %d (lost %d bytes)",
			n, payloadSize, payloadSize-n)
	}
}

func benchmarkTCPProxy(size int, b *testing.B) {
	// create and start the echo backend
	backend, err := net.Listen("tcp", testLocalhostRandomPort)
	if err != nil {
		b.Fatalf("err: %v", err)
	}
	b.Cleanup(func() {
		if closeErr := backend.Close(); closeErr != nil {
			b.Errorf("failed to close backend: %v", closeErr)
		}
	})
	go func() {
		for {
			conn, err := backend.Accept()
			if err != nil {
				break
			}
			_, err = io.Copy(conn, conn)
			if err != nil {
				b.Errorf("Failed to read entire payload: %v", err)
				return
			}
			// Can't defer since we keep accepting on each for iteration.
			if closeErr := conn.Close(); closeErr != nil {
				b.Errorf("failed to close connection: %v", closeErr)
				return
			}
		}
	}()

	// start the proxyprotocol enabled tcp proxy
	l, err := net.Listen("tcp", testLocalhostRandomPort)
	if err != nil {
		b.Fatalf("err: %v", err)
	}
	b.Cleanup(func() {
		if closeErr := l.Close(); closeErr != nil {
			b.Errorf("failed to close listener: %v", closeErr)
		}
	})
	pl := &Listener{Listener: l}
	go func() {
		for {
			conn, err := pl.Accept()
			if err != nil {
				break
			}
			bConn, err := net.Dial("tcp", backend.Addr().String())
			if err != nil {
				b.Errorf("failed to dial backend: %v", err)
				return
			}
			go func() {
				_, err = io.Copy(bConn, conn)
				if err != nil {
					b.Errorf("Failed to proxy incoming data to backend: %v", err)
					return
				}
				if closeErr := bConn.(*net.TCPConn).CloseWrite(); closeErr != nil {
					b.Errorf("failed to close write: %v", closeErr)
					return
				}
			}()
			_, err = io.Copy(conn, bConn)
			if err != nil {
				panic(fmt.Sprintf("Failed to proxy data from backend: %v", err))
			}
			if closeErr := conn.Close(); closeErr != nil {
				b.Errorf("failed to close connection: %v", closeErr)
				return
			}
			if closeErr := bConn.Close(); closeErr != nil {
				b.Errorf("failed to close connection: %v", closeErr)
				return
			}
		}
	}()

	data := make([]byte, size)

	header := &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: TCPv4,
		SourceAddr: &net.TCPAddr{
			IP:   net.ParseIP(testSourceIPv4Addr),
			Port: 1000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP(testDestinationIPv4Addr),
			Port: 2000,
		},
	}

	// now for the actual benchmark
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			b.Fatalf("err: %v", err)
		}
		// Write out the header!
		if _, err := header.WriteTo(conn); err != nil {
			b.Fatalf("err: %v", err)
		}
		// send data
		go func() {
			_, err = conn.Write(data)
			if err != nil {
				b.Errorf("Failed to write data: %v", err)
				return
			}
			if closeErr := conn.(*net.TCPConn).CloseWrite(); closeErr != nil {
				b.Errorf("failed to close write: %v", closeErr)
				return
			}
		}()
		// receive data
		n, err := io.Copy(io.Discard, conn)
		if n != int64(len(data)) {
			b.Fatalf("Expected to receive %d bytes, got %d", len(data), n)
		}
		if err != nil {
			b.Fatalf("Failed to read data: %v", err)
		}
		if closeErr := conn.Close(); closeErr != nil {
			b.Errorf("failed to close connection: %v", closeErr)
			return
		}
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

// copied from src/net/http/internal/testcert.go.

// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// LocalhostCert is a PEM-encoded TLS cert with SAN IPs "127.0.0.1" and "[::1]",
// expiring at Jan 29 16:00:00 2084 GMT. Generated from src/crypto/tls:
// go run generate_cert.go  --rsa-bits 1024 --host 127.0.0.1,::1,example.com --ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h.
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
