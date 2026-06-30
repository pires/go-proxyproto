// Package main provides a proxyproto + TLS client example.
//
// It mirrors the common upstream behavior demonstrated by the tlsserver example:
// the PROXY protocol header is written in cleartext FIRST, and the TLS handshake
// only starts afterwards. This is what a proxy such as AWS NLB (proxy protocol
// v2) or HAProxy ("send-proxy") does in front of a TLS backend.
//
// Run the tlsserver example first, then run this client.
package main

import (
	"crypto/tls"
	"io"
	"log"
	"net"

	proxyproto "github.com/pires/go-proxyproto"
)

const target = "localhost:9877"

func main() {
	// Open a raw TCP connection. The PROXY header travels in cleartext, so it
	// must be written before TLS is started.
	raw, err := net.Dial("tcp", target)
	if err != nil {
		log.Fatalf("couldn't dial %q: %v", target, err)
	}
	defer func() {
		if err := raw.Close(); err != nil {
			log.Printf("failed to close connection: %v", err)
		}
	}()

	// Describe the real client behind this proxy. Use HeaderProxyFromAddrs() if
	// you already have the source/destination conns.
	header := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.TCPv4,
		SourceAddr:        &net.TCPAddr{IP: net.ParseIP("10.1.1.1"), Port: 1000},
		DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("20.2.2.2"), Port: 2000},
	}
	if _, err := header.WriteTo(raw); err != nil {
		log.Fatalf("failed to write PROXY header: %v", err)
	}

	// Now start TLS over the same connection. InsecureSkipVerify is used only
	// because the server presents a throwaway self-signed certificate.
	conn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // example uses a throwaway self-signed cert.
	})
	if err := conn.Handshake(); err != nil {
		log.Fatalf("TLS handshake failed: %v", err)
	}

	if _, err := io.WriteString(conn, "HELO over TLS"); err != nil {
		log.Fatalf("failed to write payload: %v", err)
	}
	log.Print("sent payload over TLS")
}
