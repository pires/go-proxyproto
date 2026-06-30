// Package main provides a proxyproto + TLS server example.
//
// It demonstrates the common wrapping order: the upstream sends the PROXY
// protocol header in cleartext BEFORE the TLS handshake (e.g. AWS NLB with
// proxy protocol v2, or HAProxy "send-proxy" in front of a TLS listener). The
// proxyproto listener must therefore sit INSIDE the TLS listener, so it can
// read the header from cleartext before TLS decrypts the rest of the stream:
//
//	tls.NewListener(&proxyproto.Listener{Listener: l}, cfg) // proxyproto INNER, tls OUTER
//
// If your upstream instead sends the PROXY header INSIDE the TLS session (after
// the handshake), invert the wrapping so TLS is decrypted first:
//
//	&proxyproto.Listener{Listener: tls.NewListener(l, cfg)} // tls INNER, proxyproto OUTER
//
// Run this alongside the tlsclient example.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"log"
	"math/big"
	"net"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

const addr = "localhost:9877"

func main() {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("couldn't listen on %q: %v", addr, err)
	}

	// proxyproto INNER, tls OUTER. The PROXY header is parsed from cleartext by
	// proxyListener; tlsListener then performs the handshake on what remains.
	proxyListener := &proxyproto.Listener{Listener: l}
	tlsListener := tls.NewListener(proxyListener, selfSignedConfig())
	defer func() {
		if err := tlsListener.Close(); err != nil {
			log.Printf("failed to close listener: %v", err)
		}
	}()

	log.Printf("listening on %s", addr)
	for {
		conn, err := tlsListener.Accept()
		if err != nil {
			log.Fatalf("failed to accept connection: %v", err)
		}
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("failed to close connection: %v", err)
		}
	}()

	// conn is a *tls.Conn backed by a *proxyproto.Conn. RemoteAddr() reports the
	// real client carried by the PROXY header, not the upstream proxy. The first
	// Read transparently parses the header and completes the TLS handshake.
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("read from %s failed: %v", conn.RemoteAddr(), err)
		return
	}
	log.Printf("received %q from real client %s", buf[:n], conn.RemoteAddr())
}

// selfSignedConfig returns a *tls.Config with a throwaway self-signed
// certificate so the example runs without external files. Real servers load a
// real certificate, e.g. via tls.LoadX509KeyPair.
func selfSignedConfig() *tls.Config {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("failed to create certificate: %v", err)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  priv,
		}},
	}
}
