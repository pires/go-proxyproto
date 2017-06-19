// Package proxyproto implements Proxy Protocol (v1 and v2) parser and writer, as per specification:
// http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt
package proxyproto

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"time"
)

var (
	// Protocol
	SIGV1 = []byte{'\x50', '\x52', '\x4F', '\x58', '\x59'}
	SIGV2 = []byte{'\x0D', '\x0A', '\x0D', '\x0A', '\x00', '\x0D', '\x0A', '\x51', '\x55', '\x49', '\x54', '\x0A'}

	ErrCantReadProtocolVersionAndCommand    = errors.New("Can't read proxy protocol version and command")
	ErrCantReadAddressFamilyAndProtocol     = errors.New("Can't read address family or protocol")
	ErrCantReadLength                       = errors.New("Can't read length")
	ErrCantResolveSourceUnixAddress         = errors.New("Can't resolve source Unix address")
	ErrCantResolveDestinationUnixAddress    = errors.New("Can't resolve destination Unix address")
	ErrNoProxyProtocol                      = errors.New("Proxy protocol signature not present")
	ErrUnknownProxyProtocolVersion          = errors.New("Unknown proxy protocol version")
	ErrUnsupportedProtocolVersionAndCommand = errors.New("Unsupported proxy protocol version and command")
	ErrUnsupportedAddressFamilyAndProtocol  = errors.New("Unsupported address family and protocol")
	ErrInvalidLength                        = errors.New("Invalid length")
	ErrInvalidAddress                       = errors.New("Invalid address")
	ErrInvalidPortNumber                    = errors.New("Invalid port number")
)

type header interface {
	Version() int
	RemoteAddr() net.Addr
	LocalAddr() net.Addr
	Format() ([]byte, error)
}

func NewHeaderFromConn(conn net.Conn, version byte, command ProtocolVersionAndCommand) (hdr *v1header) {
	hdr = &v1header{
		command: command,
	}

	switch conn.RemoteAddr().(type) {
	case *net.UnixAddr:
		hdr.transportProtocol = UnixStream
	case *net.TCPAddr:
		hdr.transportProtocol = TCPv6
		if conn.RemoteAddr().(*net.TCPAddr).IP.To4() != nil {
			hdr.transportProtocol = TCPv4
		}

		hdr.sourceAddress = conn.RemoteAddr().(*net.TCPAddr).IP
		hdr.sourcePort = uint16(conn.RemoteAddr().(*net.TCPAddr).Port)
		hdr.destinationAddress = conn.LocalAddr().(*net.TCPAddr).IP
		hdr.destinationPort = uint16(conn.LocalAddr().(*net.TCPAddr).Port)
	case *net.UDPAddr:
		hdr.transportProtocol = UDPv6
		if conn.RemoteAddr().(*net.UDPAddr).IP.To4() != nil {
			hdr.transportProtocol = UDPv4
		}
		hdr.sourceAddress = conn.RemoteAddr().(*net.UDPAddr).IP
		hdr.sourcePort = uint16(conn.RemoteAddr().(*net.UDPAddr).Port)
		hdr.destinationAddress = conn.LocalAddr().(*net.UDPAddr).IP
		hdr.destinationPort = uint16(conn.LocalAddr().(*net.UDPAddr).Port)
	default:
		hdr.transportProtocol = UNSPEC
	}

	return hdr
}

// Read identifies the proxy protocol version and reads the remaining of
// the header, accordingly.
//
// If proxy protocol header signature is not present, the reader buffer remains untouched
// and is safe for reading outside of this code.
//
// If proxy protocol header signature is present but an error is raised while processing
// the remaining header, assume the reader buffer to be in a corrupt state.
// Also, this operation will block until enough bytes are available for peeking.
func Read(reader *bufio.Reader) (header, error) {
	// In order to improve speed for small non-PROXYed packets, take a peek at the first byte alone.
	if b1, err := reader.Peek(1); err == nil && (bytes.Equal(b1[:1], SIGV1[:1]) || bytes.Equal(b1[:1], SIGV2[:1])) {
		if signature, err := reader.Peek(5); err == nil && bytes.Equal(signature[:5], SIGV1) {
			return parseVersion1(reader)
		} else if signature, err := reader.Peek(12); err == nil && bytes.Equal(signature[:12], SIGV2) {
			return parseVersion2(reader)
		}
	}

	return nil, ErrNoProxyProtocol
}

// ReadTimeout acts as Read but takes a timeout. If that timeout is reached, it's assumed
// there's no proxy protocol header.
func ReadTimeout(reader *bufio.Reader, timeout time.Duration) (header, error) {
	type localHeader struct {
		h header
		e error
	}
	read := make(chan *localHeader, 1)

	go func() {
		h := &localHeader{}
		h.h, h.e = Read(reader)
		read <- h
	}()

	timer := time.NewTimer(timeout)
	select {
	case result := <-read:
		timer.Stop()
		return result.h, result.e
	case <-timer.C:
		return nil, ErrNoProxyProtocol
	}
}
