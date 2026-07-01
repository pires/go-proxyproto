package proxyproto_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/pires/go-proxyproto"
)

// ExampleReadHeaderTimeout demonstrates the cancellable, low-level way to read a
// PROXY protocol header directly from a net.Conn you manage yourself. Unlike the
// deprecated ReadTimeout, it is given the conn and sets a real read deadline, so
// a peer that connects but never sends the header cannot block the read forever.
func ExampleReadHeaderTimeout() {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()

	go func() {
		// A PROXY v1 header naming the real client, followed by application data.
		_, _ = clientConn.Write([]byte(proxyV1Line))
		_, _ = clientConn.Write([]byte("HELO"))
		_ = clientConn.Close()
	}()

	// reader must be buffered over conn: any bytes read past the header remain
	// available for the caller to consume afterwards.
	reader := bufio.NewReader(serverConn)
	header, err := proxyproto.ReadHeaderTimeout(serverConn, reader, time.Second)
	if err != nil && err != proxyproto.ErrNoProxyProtocol {
		fmt.Println("error:", err)
		return
	}
	if header != nil {
		fmt.Println("client:", header.SourceAddr)
	}

	// Continue reading the application data from the same buffered reader.
	data, _ := io.ReadAll(reader)
	fmt.Printf("data: %s\n", data)
	// Output:
	// client: 192.168.1.1:12345
	// data: HELO
}
