// Package main provides a proxyproto UDP server example.
package main

import (
	"log"
	"net"

	proxyproto "github.com/pires/go-proxyproto"
)

func main() {
	// Create a UDP socket. The PROXY protocol over UDP has no connection
	// state: the header travels in every datagram, so the socket stays a
	// plain net.PacketConn and each datagram is parsed independently.
	// The literal 127.0.0.1 matches the client in examples/udpclient;
	// "localhost" may resolve to ::1 and leave the pair on different
	// loopback sockets.
	addr := "127.0.0.1:9877"
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("couldn't resolve %q: %q\n", addr, err.Error())
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("couldn't listen to %q: %q\n", addr, err.Error())
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("failed to close connection: %v", err)
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, raddr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Fatalf("failed to read datagram: %v", err)
		}

		// Parse the PROXY header at the start of the datagram. The spec
		// forbids guessing whether a header is present: a datagram without a
		// valid header is dropped, never treated as raw payload.
		header, payload, err := proxyproto.ParseUDPDatagram(buf[:n])
		if err != nil {
			log.Printf("dropping datagram from %q: %v", raddr, err)
			continue
		}

		// raddr is the proxy that relayed the datagram; the header carries
		// the original client. Replies must go back to raddr — the client's
		// address is not directly reachable from here.
		log.Printf("proxy address: %q", raddr)
		log.Printf("client address: %q", header.SourceAddr)
		log.Printf("payload: %q", payload)
	}
}
