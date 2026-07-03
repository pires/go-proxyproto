// Package main provides a proxyproto UDP client example.
package main

import (
	"log"
	"net"

	proxyproto "github.com/pires/go-proxyproto"
)

func chkErr(err error) {
	if err != nil {
		log.Fatalf("Error: %s", err.Error())
	}
}

func main() {
	// Dial a receiver that understands the PROXY protocol over UDP, e.g. the
	// server in examples/udpserver.
	target, err := net.ResolveUDPAddr("udp", "127.0.0.1:9877")
	chkErr(err)

	conn, err := net.DialUDP("udp", nil, target)
	chkErr(err)

	defer func() {
		_ = conn.Close()
	}()

	// Create a proxyprotocol header. UDP families require the binary v2
	// format; v1 only covers TCP.
	header := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.UDPv4,
		SourceAddr: &net.UDPAddr{
			IP:   net.ParseIP("10.1.1.1"),
			Port: 1000,
		},
		DestinationAddr: &net.UDPAddr{
			IP:   net.ParseIP("20.2.2.2"),
			Port: 2000,
		},
	}

	// The spec requires the header and the payload to share one datagram:
	// FormatUDPDatagram renders both into a single slice, and every datagram
	// must carry its own header — one FormatUDPDatagram per Write.
	datagram, err := header.FormatUDPDatagram([]byte("HELO"))
	chkErr(err)
	_, err = conn.Write(datagram)
	chkErr(err)
}
