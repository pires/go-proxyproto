package proxyproto_test

import (
	"fmt"
	"net"

	"github.com/pires/go-proxyproto"
)

func ExampleParseUDPDatagram() {
	// A receiver behind a proxy that speaks the PROXY protocol over UDP. The
	// spec (section 2) requires the header and the proxied payload to share a
	// single datagram and the header to be parsed independently for each
	// datagram, so the socket stays a plain net.PacketConn and every ReadFrom
	// is followed by ParseUDPDatagram.
	server, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer func() { _ = server.Close() }()

	go func() {
		// The proxy side: one FormatUDPDatagram plus one Write keeps header
		// and payload in the same datagram.
		header := &proxyproto.Header{
			Version:           2,
			Command:           proxyproto.PROXY,
			TransportProtocol: proxyproto.UDPv4,
			SourceAddr:        &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345},
			DestinationAddr:   &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 443},
		}
		datagram, _ := header.FormatUDPDatagram([]byte("ping"))
		c, _ := net.Dial("udp", server.LocalAddr().String())
		if c != nil {
			_, _ = c.Write(datagram)
			_ = c.Close()
		}
	}()

	buf := make([]byte, 65535)
	n, _, _ := server.ReadFrom(buf)
	header, payload, err := proxyproto.ParseUDPDatagram(buf[:n])
	if err != nil {
		// The spec forbids guessing: a datagram without a valid header is
		// dropped, never treated as raw payload.
		fmt.Println("drop:", err)
		return
	}
	fmt.Printf("%s says %q\n", header.SourceAddr, payload)
	// Output: 192.168.1.1:12345 says "ping"
}

func ExampleHeader_FormatUDPDatagram() {
	header := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.UDPv4,
		SourceAddr:        &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345},
		DestinationAddr:   &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 443},
	}

	// The returned slice is the exact bytes to hand to a single WriteTo;
	// writing header and payload separately risks splitting them across
	// datagrams, which the spec forbids.
	datagram, err := header.FormatUDPDatagram([]byte("ping"))
	if err != nil {
		fmt.Println("format error:", err)
		return
	}

	parsed, payload, _ := proxyproto.ParseUDPDatagram(datagram)
	fmt.Printf("%d bytes on the wire: %s -> %s carrying %q\n",
		len(datagram), parsed.SourceAddr, parsed.DestinationAddr, payload)
	// Output: 32 bytes on the wire: 192.168.1.1:12345 -> 192.168.1.2:443 carrying "ping"
}
