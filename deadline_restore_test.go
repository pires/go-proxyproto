package proxyproto

import (
	"errors"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// restoreGateConn delays only the underlying deadline restoration so that a
// concurrent caller can update the deadline after readHeader loads its value.
// All I/O and deadline effects still use a real TCP connection.
type restoreGateConn struct {
	net.Conn
	calls         atomic.Int32
	restoring     chan struct{}
	release       chan struct{}
	callerApplied chan struct{}
}

func (c *restoreGateConn) SetReadDeadline(deadline time.Time) error {
	call := c.calls.Add(1)
	if call == 2 {
		close(c.restoring)
		<-c.release
	}
	err := c.Conn.SetReadDeadline(deadline)
	if call == 3 {
		close(c.callerApplied)
	}
	return err
}

func TestConcurrentHeaderDeadlineRestore(t *testing.T) {
	for _, setAll := range []bool{false, true} {
		name := "SetReadDeadline"
		if setAll {
			name = "SetDeadline"
		}
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			client, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = client.Close() }()
			server, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = server.Close() }()
			gate := &restoreGateConn{Conn: server, restoring: make(chan struct{}), release: make(chan struct{}), callerApplied: make(chan struct{})}
			t.Cleanup(func() {
				select {
				case <-gate.release:
				default:
					close(gate.release)
				}
			})
			p := NewConn(gate, SetReadHeaderTimeout(time.Second))
			readDone := make(chan error, 1)
			go func() { var b [1]byte; _, err := p.Read(b[:]); readDone <- err }()
			if _, err := client.Write([]byte("PROXY TCP4 192.0.2.1 192.0.2.2 1234 4321\r\n")); err != nil {
				t.Fatal(err)
			}
			select {
			case <-gate.restoring:
			case <-time.After(2 * time.Second):
				t.Fatal("header was not parsed")
			}
			setterStarted := make(chan struct{})
			setterDone := make(chan error, 1)
			go func() {
				close(setterStarted)
				if setAll {
					setterDone <- p.SetDeadline(time.Now().Add(-time.Second))
				} else {
					setterDone <- p.SetReadDeadline(time.Now().Add(-time.Second))
				}
			}()
			<-setterStarted
			// On the base the caller applies its deadline before the paused stale
			// restore. With serialization it waits until the restore completes.
			if !setAll {
				select {
				case <-gate.callerApplied:
				case <-time.After(50 * time.Millisecond):
				}
			} else {
				select {
				case err := <-setterDone:
					if err != nil {
						t.Fatal(err)
					}
					setterDone <- nil
				case <-time.After(50 * time.Millisecond):
				}
			}
			close(gate.release)
			if err := <-setterDone; err != nil {
				t.Fatal(err)
			}
			// Do not send application bytes while waiting for the timeout: data
			// arriving alongside the deadline wakeup can satisfy an already
			// pending TCP read before it observes the timeout.
			select {
			case err := <-readDone:
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Errorf("Read after expired caller deadline = %v, want deadline exceeded", err)
				}
			case <-time.After(time.Second):
				t.Error("Read ignored caller deadline")
				_ = server.Close()
				_ = <-readDone
			}
		})
	}
}
