package proxyproto_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// ExampleListener_tls shows how to combine the PROXY protocol with TLS.
//
// The only real decision is the listener wrapping order, and it depends on where
// the upstream places the PROXY header relative to the TLS handshake:
//
//   - Header in cleartext, BEFORE the handshake. This is the common case (e.g.
//     AWS NLB with proxy protocol v2, or HAProxy "send-proxy" in front of a TLS
//     listener). proxyproto must read the header first, so it goes INSIDE the
//     TLS listener: tls.NewListener(&proxyproto.Listener{...}, cfg).
//
//   - Header INSIDE the TLS session, AFTER the handshake. TLS must be decrypted
//     first, so proxyproto goes OUTSIDE the TLS listener:
//     &proxyproto.Listener{Listener: tls.NewListener(l, cfg)}.
//
// This example demonstrates the first (cleartext-header) ordering, which is what
// most deployments need. Because the header is parsed before TLS,
// conn.RemoteAddr() reports the real client address carried by the PROXY header
// rather than the immediate peer (the proxy). See
// ExampleListener_tlsHeaderInsideTLS for the second ordering.
func ExampleListener_tls() {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return
	}

	// proxyproto INNER, tls OUTER: the PROXY header is read from cleartext, then
	// the TLS handshake runs on the remaining stream.
	proxyListener := &proxyproto.Listener{Listener: l}
	tlsListener := tls.NewListener(proxyListener, exampleSelfSignedConfig())
	defer func() { _ = tlsListener.Close() }()

	go func() {
		// Client side: open a raw TCP connection, write the PROXY header in
		// cleartext, and only THEN start the TLS handshake.
		raw, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			return
		}
		defer func() { _ = raw.Close() }()

		header := &proxyproto.Header{
			Version:           2,
			Command:           proxyproto.PROXY,
			TransportProtocol: proxyproto.TCPv4,
			SourceAddr:        &net.TCPAddr{IP: net.ParseIP("10.1.1.1"), Port: 1000},
			DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("20.2.2.2"), Port: 2000},
		}
		if _, err := header.WriteTo(raw); err != nil {
			return
		}

		client := tls.Client(raw, &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // example uses a throwaway self-signed cert.
		})
		_ = client.Handshake()
		_ = client.Close()
	}()

	conn, err := tlsListener.Accept()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()

	// conn is a *tls.Conn whose underlying connection is a *proxyproto.Conn that
	// has already parsed the header, so RemoteAddr() is the real client. From
	// here, use conn like any other tls.Conn (Read/Write) to serve the client.
	fmt.Println(conn.RemoteAddr())
	// Output: 10.1.1.1:1000
}

// ExampleListener_tlsHeaderInsideTLS shows the second wrapping order, where the
// upstream completes the TLS handshake first and only then sends the PROXY
// header inside the encrypted session. TLS must be decrypted before the header
// can be read, so proxyproto wraps the TLS listener: proxyproto OUTER, tls INNER
// (the inverse of ExampleListener_tls). Use this only when you control the
// upstream and it deliberately speaks the header after the handshake.
func ExampleListener_tlsHeaderInsideTLS() {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return
	}

	// tls INNER, proxyproto OUTER: TLS is decrypted first, then the PROXY header
	// is parsed from the decrypted stream.
	proxyListener := &proxyproto.Listener{
		Listener: tls.NewListener(l, exampleSelfSignedConfig()),
	}
	defer func() { _ = proxyListener.Close() }()

	go func() {
		// Client side: complete the TLS handshake first, then write the PROXY
		// header inside the encrypted session.
		raw, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			return
		}
		defer func() { _ = raw.Close() }()

		client := tls.Client(raw, &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // example uses a throwaway self-signed cert.
		})
		if err := client.Handshake(); err != nil {
			return
		}

		header := &proxyproto.Header{
			Version:           2,
			Command:           proxyproto.PROXY,
			TransportProtocol: proxyproto.TCPv4,
			SourceAddr:        &net.TCPAddr{IP: net.ParseIP("10.1.1.1"), Port: 1000},
			DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("20.2.2.2"), Port: 2000},
		}
		_, _ = header.WriteTo(client)
		_ = client.Close()
	}()

	conn, err := proxyListener.Accept()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()

	// conn is a *proxyproto.Conn wrapping a *tls.Conn. Reading the header (here
	// via RemoteAddr) transparently runs the TLS handshake, decrypts the stream,
	// and then parses the PROXY header, so RemoteAddr() is the real client.
	fmt.Println(conn.RemoteAddr())
	// Output: 10.1.1.1:1000
}

// exampleSelfSignedConfig returns a *tls.Config with a throwaway self-signed
// certificate, so the example is self-contained. Real servers load a real
// certificate, e.g. via tls.LoadX509KeyPair.
func exampleSelfSignedConfig() *tls.Config {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  priv,
		}},
	}
}
