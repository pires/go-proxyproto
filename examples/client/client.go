package main

import (
	"io"
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
	// Dial some proxy listener e.g. https://github.com/mailgun/proxyproto
	target, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9876")
	chkErr(err)

	conn, err := net.DialTCP("tcp", nil, target)
	chkErr(err)

	defer conn.Close()

	// Create a proxyprotocol header or use HeaderProxyFromAddrs() if you
	// have two conn's
	header := &proxyproto.Header{
		Version:           1,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.TCPv4,
		SourceAddr: &net.TCPAddr{
			IP:   net.ParseIP("10.1.1.1"),
			Port: 1000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP("20.2.2.2"),
			Port: 2000,
		},
	}
	// After the connection was created write the proxy headers first
	_, err = header.WriteTo(conn)
	chkErr(err)
	// Then your data... e.g.:
	_, err = io.WriteString(conn, "HELO")
	chkErr(err)
}
