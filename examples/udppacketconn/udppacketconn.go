// Package main sketches a net.PacketConn wrapper for the PROXY protocol over
// UDP.
//
// The library deliberately ships only ParseUDPDatagram and
// Header.FormatUDPDatagram. A full wrapper has to answer a question the spec
// does not: ReadFrom reports the client address carried by the header, but
// replies must travel to the proxy that relayed the datagram, so WriteTo
// needs a client→proxy flow table — and its bounds, expiry, and spoofing
// exposure are application policy. This example shows the shape of such a
// wrapper with the simplest possible policy, so you can adapt it rather than
// import an opinion.
package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// proxyPacketConn wraps a net.PacketConn whose peers prepend a PROXY protocol
// header to every datagram, per spec section 2.
//
// ReadFrom returns the client address carried by the header; WriteTo accepts
// that same address and routes the reply to the proxy that last relayed for
// it. Replies carry no header: the PROXY protocol travels one way, from the
// party that knows the client address to the party that needs it.
type proxyPacketConn struct {
	net.PacketConn

	mu    sync.Mutex
	flows map[string]net.Addr // client address (from header) -> relaying proxy
}

func newProxyPacketConn(inner net.PacketConn) *proxyPacketConn {
	return &proxyPacketConn{PacketConn: inner, flows: make(map[string]net.Addr)}
}

// ReadFrom reads one datagram, parses its PROXY header, and returns the
// proxied payload with the client address the header carries. Datagrams
// without a valid header are dropped and the read continues: the spec forbids
// guessing, so they must never surface as raw payload.
func (c *proxyPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	// The header is a prefix of the datagram, so parsing needs the whole
	// datagram in one buffer before the payload can be copied into p.
	buf := make([]byte, 65535)
	for {
		n, proxyAddr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}

		header, payload, err := proxyproto.ParseUDPDatagram(buf[:n])
		if err != nil {
			log.Printf("dropping datagram from %q: %v", proxyAddr, err)
			continue
		}

		// LOCAL datagrams (e.g. proxy health checks) carry the proxy's own
		// traffic, so the proxy itself is the peer. Record it as its own flow
		// so a reply through WriteTo routes like any other address ReadFrom
		// has returned.
		if header.Command.IsLocal() || header.SourceAddr == nil {
			c.mu.Lock()
			c.flows[proxyAddr.String()] = proxyAddr
			c.mu.Unlock()
			return copy(p, payload), proxyAddr, nil
		}

		// Policy decisions start here, and they are why this lives in an
		// example: the table below never expires entries and grows with every
		// distinct client address, which a peer sending forged headers can
		// inflate at will. A real application bounds it, expires idle flows,
		// and only accepts headers from trusted proxy addresses (compare
		// TrustProxyHeaderFromRanges for the stream side).
		c.mu.Lock()
		c.flows[header.SourceAddr.String()] = proxyAddr
		c.mu.Unlock()

		// copy truncates silently when p is too small, as UDP reads do.
		return copy(p, payload), header.SourceAddr, nil
	}
}

// WriteTo sends a reply to a client address previously returned by ReadFrom,
// routing it to the proxy that relayed for that client.
func (c *proxyPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	proxyAddr, ok := c.flows[addr.String()]
	c.mu.Unlock()
	if !ok {
		return 0, fmt.Errorf("no known proxy for client %q", addr)
	}
	return c.PacketConn.WriteTo(p, proxyAddr)
}

func main() {
	inner, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		log.Fatalf("couldn't listen: %v", err)
	}
	server := newProxyPacketConn(inner)
	defer func() {
		if err := server.Close(); err != nil {
			log.Printf("failed to close server: %v", err)
		}
	}()

	// Echo server: the wrapper makes this loop look like plain UDP code even
	// though every datagram arrives with a PROXY header and every reply is
	// re-routed through the relaying proxy.
	go func() {
		buf := make([]byte, 65535)
		for {
			n, clientAddr, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			log.Printf("server: %q from client %q", buf[:n], clientAddr)
			if _, err := server.WriteTo(buf[:n], clientAddr); err != nil {
				log.Printf("server: reply failed: %v", err)
			}
		}
	}()

	// Two proxies, each relaying for a different client, prove replies find
	// their way back through the flow table.
	clients := []*net.UDPAddr{
		{IP: net.ParseIP("10.1.1.1"), Port: 1000},
		{IP: net.ParseIP("10.2.2.2"), Port: 2000},
	}
	for i, clientAddr := range clients {
		proxy, err := net.DialUDP("udp", nil, inner.LocalAddr().(*net.UDPAddr))
		if err != nil {
			log.Fatalf("proxy %d: dial failed: %v", i, err)
		}

		header := &proxyproto.Header{
			Version:           2,
			Command:           proxyproto.PROXY,
			TransportProtocol: proxyproto.UDPv4,
			SourceAddr:        clientAddr,
			DestinationAddr:   &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 443},
		}
		datagram, err := header.FormatUDPDatagram(fmt.Appendf(nil, "ping %d", i))
		if err != nil {
			log.Fatalf("proxy %d: format failed: %v", i, err)
		}
		if _, err := proxy.Write(datagram); err != nil {
			log.Fatalf("proxy %d: write failed: %v", i, err)
		}

		// The echo comes back to the proxy socket, headerless.
		reply := make([]byte, 65535)
		_ = proxy.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := proxy.Read(reply)
		if err != nil {
			log.Fatalf("proxy %d: no echo: %v", i, err)
		}
		log.Printf("proxy %d: echo %q for client %q", i, reply[:n], clientAddr)
		_ = proxy.Close()
	}

	// A LOCAL datagram (e.g. a proxy health check) carries the proxy's own
	// traffic: ReadFrom reports the proxy as the peer and the echo returns
	// straight to it, no client involved.
	proxy, err := net.DialUDP("udp", nil, inner.LocalAddr().(*net.UDPAddr))
	if err != nil {
		log.Fatalf("health check: dial failed: %v", err)
	}
	defer func() { _ = proxy.Close() }()
	local := &proxyproto.Header{Version: 2, Command: proxyproto.LOCAL, TransportProtocol: proxyproto.UNSPEC}
	datagram, err := local.FormatUDPDatagram([]byte("health"))
	if err != nil {
		log.Fatalf("health check: format failed: %v", err)
	}
	if _, err := proxy.Write(datagram); err != nil {
		log.Fatalf("health check: write failed: %v", err)
	}
	reply := make([]byte, 65535)
	_ = proxy.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := proxy.Read(reply)
	if err != nil {
		log.Fatalf("health check: no echo: %v", err)
	}
	log.Printf("health check: echo %q", reply[:n])
}
