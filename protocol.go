package proxyproto

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"
	"time"
)

// Listener is used to wrap an underlying listener,
// whose connections may be using the HAProxy Proxy Protocol (version 1).
// If the connection is using the protocol, the RemoteAddr() will return
// the correct client address.
//
// Optionally define ProxyHeaderTimeout to set a maximum time to
// receive the Proxy Protocol v1header. Zero means no timeout.
type Listener struct {
	Listener           net.Listener
	ProxyHeaderTimeout time.Duration
}

// Conn is used to wrap and underlying connection which
// may be speaking the Proxy Protocol. If it is, the RemoteAddr() will
// return the address of the client instead of the proxy address.
type Conn struct {
	bufReader          *bufio.Reader
	conn               net.Conn
	header             header
	once               sync.Once
	proxyHeaderTimeout time.Duration

	TLS *tls.ConnectionState
}

// Accept waits for and returns the next connection to the listener.
func (p *Listener) Accept() (net.Conn, error) {
	// Get the underlying connection
	conn, err := p.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewConn(conn, p.ProxyHeaderTimeout), nil
}

// Close closes the underlying listener.
func (p *Listener) Close() error {
	return p.Listener.Close()
}

// Addr returns the underlying listener's network address.
func (p *Listener) Addr() net.Addr {
	return p.Listener.Addr()
}

// NewConn is used to wrap a net.Conn that may be speaking
// the proxy protocol into a proxyproto.Conn
func NewConn(conn net.Conn, timeout time.Duration) *Conn {
	pConn := &Conn{
		bufReader:          bufio.NewReader(conn),
		conn:               conn,
		proxyHeaderTimeout: timeout,
	}
	return pConn
}

// Read is check for the proxy protocol header when doing
// the initial scan. If there is an error parsing the header,
// it is returned and the socket is closed.
func (c *Conn) Read(b []byte) (int, error) {
	var err error
	c.once.Do(func() {
		err = c.readHeader()
	})
	if err != nil {
		return 0, err
	}
	return c.bufReader.Read(b)
}

func (c *Conn) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

func (c *Conn) Close() error {
	return c.conn.Close()
}

func (c *Conn) LocalAddr() net.Addr {
	c.once.Do(func() { c.readHeader() })
	if c.header == nil {
		return c.conn.LocalAddr()
	}

	return c.header.LocalAddr()
}

// RemoteAddr returns the address of the client if the proxy
// protocol is being used, otherwise just returns the address of
// the socket peer.
func (c *Conn) RemoteAddr() net.Addr {
	c.once.Do(func() { c.readHeader() })
	if c.header == nil {
		return c.conn.RemoteAddr()
	}

	return c.header.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *Conn) readHeader() error {
	hdr, err := Read(c.bufReader)
	if err != nil {
		return err
	}
	c.header = hdr

	if v2Hdr, ok := hdr.(*v2header); ok && v2Hdr.SslClientSsl {
		c.setTlsStateFromHeader(v2Hdr)
	}

	return nil
}

func (c *Conn) setTlsStateFromHeader(hdr *v2header) {
	c.TLS = &tls.ConnectionState{
		Version:                     tls.VersionTLS12, // TODO: Convert from string to uint16?
		HandshakeComplete:           true,
		DidResume:                   hdr.SslClientCertConn == false,
		CipherSuite:                 0,    // TODO: Convert from string to uint16?
		NegotiatedProtocol:          "",   // TODO
		NegotiatedProtocolIsMutual:  true, // TODO
		ServerName:                  hdr.Authority,
		PeerCertificates:            make([]*x509.Certificate, 0),
		VerifiedChains:              make([][]*x509.Certificate, 0),
		SignedCertificateTimestamps: make([][]byte, 0),
		OCSPResponse:                make([]byte, 0),
		TLSUnique:                   make([]byte, 0),
	}
}
