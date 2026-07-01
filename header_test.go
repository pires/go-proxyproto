package proxyproto

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"
)

// Stuff to be used in both versions tests.

const (
	testNoProtocol          = "There is no spoon"
	testLocalhostIP4Addr    = "127.0.0.1"
	testLocalhostIP4In6Addr = "::ffff:127.0.0.1"
	testLocalhostIP6Addr    = "::1"
	testIP6LongAddr         = "1234:5678:9abc:def0:cafe:babe:dead:2bad"
	testValidPort           = 65533
	testInvalidPort         = 99999

	// Unix-domain address names reused across address fixtures in tests.
	testUnixSocketName = "socket"
	testUnixSrcName    = "src"
	testUnixDstName    = "dst"
)

var (
	v4ip = net.ParseIP(testLocalhostIP4Addr).To4()
	v6ip = net.ParseIP(testLocalhostIP6Addr).To16()

	v4addr net.Addr = &net.TCPAddr{IP: v4ip, Port: testValidPort}
	v6addr net.Addr = &net.TCPAddr{IP: v6ip, Port: testValidPort}

	v4UDPAddr net.Addr = &net.UDPAddr{IP: v4ip, Port: testValidPort}
	v6UDPAddr net.Addr = &net.UDPAddr{IP: v6ip, Port: testValidPort}

	unixStreamAddr   net.Addr = &net.UnixAddr{Net: networkUnix, Name: testUnixSocketName}
	unixDatagramAddr net.Addr = &net.UnixAddr{Net: networkUnixgram, Name: testUnixSocketName}

	errReadIntentionallyBroken = errors.New("read is intentionally broken")
)

type timeoutReader []byte

func (t *timeoutReader) Read([]byte) (int, error) {
	time.Sleep(500 * time.Millisecond)
	return 0, nil
}

type errorReader []byte

func (e *errorReader) Read([]byte) (int, error) {
	return 0, errReadIntentionallyBroken
}

func TestReadTimeoutV1Invalid(t *testing.T) {
	var b timeoutReader
	reader := bufio.NewReader(&b)
	_, err := ReadTimeout(reader, 50*time.Millisecond)
	if err == nil {
		t.Fatalf("expected error %s", ErrNoProxyProtocol)
	} else if err != ErrNoProxyProtocol {
		t.Fatalf("expected %s, actual %s", ErrNoProxyProtocol, err)
	}
}

func TestReadTimeoutPropagatesReadError(t *testing.T) {
	var e errorReader
	reader := bufio.NewReader(&e)
	_, err := ReadTimeout(reader, 50*time.Millisecond)

	if err == nil {
		t.Fatalf("expected error %s", errReadIntentionallyBroken)
	} else if err != errReadIntentionallyBroken {
		t.Fatalf("expected error %s, actual %s", errReadIntentionallyBroken, err)
	}
}

func TestReadHeaderTimeoutParsesHeaderAndPreservesPayload(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	const payload = "hello"
	go func() {
		_, _ = client.Write([]byte("PROXY TCP4 127.0.0.1 127.0.0.2 12345 443\r\n" + payload))
		_ = client.Close()
	}()

	reader := bufio.NewReader(server)
	h, err := ReadHeaderTimeout(server, reader, time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil || h.Version != 1 {
		t.Fatalf("expected a v1 header, got %+v", h)
	}

	// Bytes buffered past the header must remain readable by the caller.
	got := make([]byte, len(payload))
	n, err := reader.Read(got)
	if err != nil {
		t.Fatalf("reading buffered payload: %v", err)
	}
	if string(got[:n]) != payload {
		t.Fatalf("expected payload %q, got %q", payload, string(got[:n]))
	}
}

func TestReadHeaderTimeoutCancelsStalledRead(t *testing.T) {
	// The peer connects but never sends anything. Without a real deadline this
	// would block forever (the failure the deprecated ReadTimeout leaks on);
	// ReadHeaderTimeout has the conn, so its deadline actually fires.
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	reader := bufio.NewReader(server)
	start := time.Now()
	h, err := ReadHeaderTimeout(server, reader, 50*time.Millisecond)
	elapsed := time.Since(start)

	if err != ErrNoProxyProtocol {
		t.Fatalf("expected %v, got %v", ErrNoProxyProtocol, err)
	}
	if h != nil {
		t.Fatalf("expected nil header, got %+v", h)
	}
	// Generous slack for slow CI; the point is that it returns at all.
	if elapsed > 2*time.Second {
		t.Fatalf("read did not cancel promptly: elapsed=%v", elapsed)
	}
}

func TestReadHeaderTimeoutNoHeaderPreservesData(t *testing.T) {
	// The peer sends non-PROXY data. ReadHeaderTimeout must report "no header"
	// without consuming those bytes, so the caller can still read them.
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	const want = "GET / HTTP/1.1\r\n"
	go func() {
		_, _ = client.Write([]byte(want))
		_ = client.Close()
	}()

	reader := bufio.NewReader(server)
	h, err := ReadHeaderTimeout(server, reader, time.Second)
	if err != ErrNoProxyProtocol {
		t.Fatalf("expected %v, got %v", ErrNoProxyProtocol, err)
	}
	if h != nil {
		t.Fatalf("expected nil header, got %+v", h)
	}

	got := make([]byte, len(want))
	n, err := reader.Read(got)
	if err != nil {
		t.Fatalf("reading preserved data: %v", err)
	}
	if string(got[:n]) != want {
		t.Fatalf("non-PROXY data not preserved: got %q", string(got[:n]))
	}
}

func TestReadHeaderTimeoutZeroTimeoutReadsWithoutDeadline(t *testing.T) {
	// A timeout <= 0 must skip the deadline entirely and still read a header.
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	go func() {
		_, _ = client.Write([]byte("PROXY TCP4 10.1.1.1 20.2.2.2 1000 2000\r\n"))
		_ = client.Close()
	}()

	reader := bufio.NewReader(server)
	h, err := ReadHeaderTimeout(server, reader, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil || h.SourceAddr.String() != "10.1.1.1:1000" {
		t.Fatalf("unexpected header: %+v", h)
	}
}

func TestReadHeaderTimeoutInitialDeadlineError(t *testing.T) {
	// If arming the deadline fails, the error is returned and no read is done.
	inner := &deadlineFailConn{
		r:         bytes.NewReader([]byte("PROXY TCP4 10.1.1.1 20.2.2.2 1000 2000\r\n")),
		failOnSet: 1,
	}
	reader := bufio.NewReader(inner)
	if _, err := ReadHeaderTimeout(inner, reader, time.Second); !errors.Is(err, errDeadlineFail) {
		t.Fatalf("expected the SetReadDeadline error, got %v", err)
	}
	if inner.setCalls != 1 {
		t.Fatalf("expected exactly one SetReadDeadline call, got %d", inner.setCalls)
	}
}

func TestReadHeaderTimeoutPropagatesParseError(t *testing.T) {
	// A valid PROXY v1 signature but an invalid body must surface the parse
	// error, not be masked as ErrNoProxyProtocol.
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	go func() {
		_, _ = client.Write([]byte("PROXY TCP4 10.1.1.1 20.2.2.2 notaport 2000\r\n"))
		_ = client.Close()
	}()

	reader := bufio.NewReader(server)
	_, err := ReadHeaderTimeout(server, reader, time.Second)
	if err == nil || err == ErrNoProxyProtocol {
		t.Fatalf("expected a parse error, got %v", err)
	}
}

func TestEqualsTo(t *testing.T) {
	var headersEqual = []struct {
		this, that *Header
		expected   bool
	}{
		{
			&Header{
				Version:           1,
				Command:           PROXY,
				TransportProtocol: TCPv4,
				SourceAddr: &net.TCPAddr{
					IP:   net.ParseIP(testSourceIPv4Addr),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP(testDestinationIPv4Addr),
					Port: 2000,
				},
			},
			nil,
			false,
		},
		{
			&Header{
				Version:           1,
				Command:           PROXY,
				TransportProtocol: TCPv4,
				SourceAddr: &net.TCPAddr{
					IP:   net.ParseIP(testSourceIPv4Addr),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP(testDestinationIPv4Addr),
					Port: 2000,
				},
			},
			&Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: TCPv4,
				SourceAddr: &net.TCPAddr{
					IP:   net.ParseIP(testSourceIPv4Addr),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP(testDestinationIPv4Addr),
					Port: 2000,
				},
			},
			false,
		},
		{
			&Header{
				Version:           1,
				Command:           PROXY,
				TransportProtocol: TCPv4,
				SourceAddr: &net.TCPAddr{
					IP:   net.ParseIP(testSourceIPv4Addr),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP(testDestinationIPv4Addr),
					Port: 2000,
				},
			},
			&Header{
				Version:           1,
				Command:           PROXY,
				TransportProtocol: TCPv4,
				SourceAddr: &net.TCPAddr{
					IP:   net.ParseIP(testSourceIPv4Addr),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP(testDestinationIPv4Addr),
					Port: 2000,
				},
			},
			true,
		},
	}

	for _, tt := range headersEqual {
		if actual := tt.this.EqualsTo(tt.that); actual != tt.expected {
			t.Fatalf("expected %t, actual %t", tt.expected, actual)
		}
	}
}

// This is here just because of coveralls.
func TestEqualTo(t *testing.T) {
	TestEqualsTo(t)
}

func TestGetters(t *testing.T) {
	var tests = []struct {
		name                         string
		header                       *Header
		tcpSourceAddr, tcpDestAddr   *net.TCPAddr
		udpSourceAddr, udpDestAddr   *net.UDPAddr
		unixSourceAddr, unixDestAddr *net.UnixAddr
		ipSource, ipDest             net.IP
		portSource, portDest         int
	}{
		{
			name: "TCPv4",
			header: &Header{
				Version:           1,
				Command:           PROXY,
				TransportProtocol: TCPv4,
				SourceAddr: &net.TCPAddr{
					IP:   net.ParseIP(testSourceIPv4Addr),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP(testDestinationIPv4Addr),
					Port: 2000,
				},
			},
			tcpSourceAddr: &net.TCPAddr{
				IP:   net.ParseIP(testSourceIPv4Addr),
				Port: 1000,
			},
			tcpDestAddr: &net.TCPAddr{
				IP:   net.ParseIP(testDestinationIPv4Addr),
				Port: 2000,
			},
			ipSource:   net.ParseIP(testSourceIPv4Addr),
			ipDest:     net.ParseIP(testDestinationIPv4Addr),
			portSource: 1000,
			portDest:   2000,
		},
		{
			name: "UDPv4",
			header: &Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: UDPv6,
				SourceAddr: &net.UDPAddr{
					IP:   net.ParseIP(testSourceIPv4Addr),
					Port: 1000,
				},
				DestinationAddr: &net.UDPAddr{
					IP:   net.ParseIP(testDestinationIPv4Addr),
					Port: 2000,
				},
			},
			udpSourceAddr: &net.UDPAddr{
				IP:   net.ParseIP(testSourceIPv4Addr),
				Port: 1000,
			},
			udpDestAddr: &net.UDPAddr{
				IP:   net.ParseIP(testDestinationIPv4Addr),
				Port: 2000,
			},
			ipSource:   net.ParseIP(testSourceIPv4Addr),
			ipDest:     net.ParseIP(testDestinationIPv4Addr),
			portSource: 1000,
			portDest:   2000,
		},
		{
			name: "UnixStream",
			header: &Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: UnixStream,
				SourceAddr: &net.UnixAddr{
					Net:  networkUnix,
					Name: testUnixSrcName,
				},
				DestinationAddr: &net.UnixAddr{
					Net:  networkUnix,
					Name: testUnixDstName,
				},
			},
			unixSourceAddr: &net.UnixAddr{
				Net:  networkUnix,
				Name: testUnixSrcName,
			},
			unixDestAddr: &net.UnixAddr{
				Net:  networkUnix,
				Name: testUnixDstName,
			},
		},
		{
			name: "UnixDatagram",
			header: &Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: UnixDatagram,
				SourceAddr: &net.UnixAddr{
					Net:  networkUnix,
					Name: testUnixSrcName,
				},
				DestinationAddr: &net.UnixAddr{
					Net:  networkUnix,
					Name: testUnixDstName,
				},
			},
			unixSourceAddr: &net.UnixAddr{
				Net:  networkUnix,
				Name: testUnixSrcName,
			},
			unixDestAddr: &net.UnixAddr{
				Net:  networkUnix,
				Name: testUnixDstName,
			},
		},
		{
			name: "Unspec",
			header: &Header{
				Version:           1,
				Command:           PROXY,
				TransportProtocol: UNSPEC,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tcpSourceAddr, tcpDestAddr, _ := test.header.TCPAddrs()
			if test.tcpSourceAddr != nil && !reflect.DeepEqual(tcpSourceAddr, test.tcpSourceAddr) {
				t.Errorf("TCPAddrs() source = %v, want %v", tcpSourceAddr, test.tcpSourceAddr)
			}
			if test.tcpDestAddr != nil && !reflect.DeepEqual(tcpDestAddr, test.tcpDestAddr) {
				t.Errorf("TCPAddrs() dest = %v, want %v", tcpDestAddr, test.tcpDestAddr)
			}

			udpSourceAddr, udpDestAddr, _ := test.header.UDPAddrs()
			if test.udpSourceAddr != nil && !reflect.DeepEqual(udpSourceAddr, test.udpSourceAddr) {
				t.Errorf("TCPAddrs() source = %v, want %v", udpSourceAddr, test.udpSourceAddr)
			}
			if test.udpDestAddr != nil && !reflect.DeepEqual(udpDestAddr, test.udpDestAddr) {
				t.Errorf("TCPAddrs() dest = %v, want %v", udpDestAddr, test.udpDestAddr)
			}

			unixSourceAddr, unixDestAddr, _ := test.header.UnixAddrs()
			if test.unixSourceAddr != nil && !reflect.DeepEqual(unixSourceAddr, test.unixSourceAddr) {
				t.Errorf("UnixAddrs() source = %v, want %v", unixSourceAddr, test.unixSourceAddr)
			}
			if test.unixDestAddr != nil && !reflect.DeepEqual(unixDestAddr, test.unixDestAddr) {
				t.Errorf("UnixAddrs() dest = %v, want %v", unixDestAddr, test.unixDestAddr)
			}

			ipSource, ipDest, _ := test.header.IPs()
			if test.ipSource != nil && !ipSource.Equal(test.ipSource) {
				t.Errorf("IPs() source = %v, want %v", ipSource, test.ipSource)
			}
			if test.ipDest != nil && !ipDest.Equal(test.ipDest) {
				t.Errorf("IPs() dest = %v, want %v", ipDest, test.ipDest)
			}

			portSource, portDest, _ := test.header.Ports()
			if test.portSource != 0 && portSource != test.portSource {
				t.Errorf("Ports() source = %v, want %v", portSource, test.portSource)
			}
			if test.portDest != 0 && portDest != test.portDest {
				t.Errorf("Ports() dest = %v, want %v", portDest, test.portDest)
			}
		})
	}
}

func TestSetTLVs(t *testing.T) {
	tests := []struct {
		header    *Header
		name      string
		tlvs      []TLV
		expectErr bool
	}{
		{
			name: "add authority TLV",
			header: &Header{
				Version:           1,
				Command:           PROXY,
				TransportProtocol: TCPv4,
				SourceAddr: &net.TCPAddr{
					IP:   net.ParseIP(testSourceIPv4Addr),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP(testDestinationIPv4Addr),
					Port: 2000,
				},
			},
			tlvs: []TLV{{
				Type:  PP2_TYPE_AUTHORITY,
				Value: []byte("example.org"),
			}},
		},
		{
			name: "add too long TLV",
			header: &Header{
				Version:           1,
				Command:           PROXY,
				TransportProtocol: TCPv4,
				SourceAddr: &net.TCPAddr{
					IP:   net.ParseIP(testSourceIPv4Addr),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP(testDestinationIPv4Addr),
					Port: 2000,
				},
			},
			tlvs: []TLV{{
				Type:  PP2_TYPE_AUTHORITY,
				Value: append(bytes.Repeat([]byte("a"), 0xFFFF), []byte(".example.org")...),
			}},
			expectErr: true,
		},
	}
	for _, tt := range tests {
		err := tt.header.SetTLVs(tt.tlvs)
		if err != nil && !tt.expectErr {
			t.Fatalf("shouldn't have thrown error %q", err.Error())
		}
	}
}

func TestWriteTo(t *testing.T) {
	var buf bytes.Buffer

	validHeader := &Header{
		Version:           1,
		Command:           PROXY,
		TransportProtocol: TCPv4,
		SourceAddr: &net.TCPAddr{
			IP:   net.ParseIP(testSourceIPv4Addr),
			Port: 1000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP(testDestinationIPv4Addr),
			Port: 2000,
		},
	}

	if _, err := validHeader.WriteTo(&buf); err != nil {
		t.Fatalf("shouldn't have thrown error %q", err.Error())
	}

	invalidHeader := &Header{
		SourceAddr: &net.TCPAddr{
			IP:   net.ParseIP(testSourceIPv4Addr),
			Port: 1000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP(testDestinationIPv4Addr),
			Port: 2000,
		},
	}

	if _, err := invalidHeader.WriteTo(&buf); err == nil {
		// err is nil in this branch, so don't format it (would nil-deref).
		t.Fatal("should have thrown error")
	}
}

func TestFormat(t *testing.T) {
	validHeader := &Header{
		Version:           1,
		Command:           PROXY,
		TransportProtocol: TCPv4,
		SourceAddr: &net.TCPAddr{
			IP:   net.ParseIP(testSourceIPv4Addr),
			Port: 1000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP(testDestinationIPv4Addr),
			Port: 2000,
		},
	}

	if _, err := validHeader.Format(); err != nil {
		t.Fatalf("shouldn't have thrown error %q", err.Error())
	}
}

func TestFormatInvalid(t *testing.T) {
	tests := []struct {
		name   string
		header *Header
		err    error
	}{
		{
			name: "invalidVersion",
			header: &Header{
				Version:           3,
				Command:           PROXY,
				TransportProtocol: TCPv4,
				SourceAddr:        v4addr,
				DestinationAddr:   v4addr,
			},
			err: ErrUnknownProxyProtocolVersion,
		},
		{
			name: "v2MismatchTCPv4_UDPv4",
			header: &Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: TCPv4,
				SourceAddr:        v4UDPAddr,
				DestinationAddr:   v4addr,
			},
			err: ErrInvalidAddress,
		},
		{
			name: "v2MismatchTCPv4_TCPv6",
			header: &Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: TCPv4,
				SourceAddr:        v4addr,
				DestinationAddr:   v6addr,
			},
			err: ErrInvalidAddress,
		},
		{
			name: "v2MismatchUnixStream_TCPv4",
			header: &Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: UnixStream,
				SourceAddr:        v4addr,
				DestinationAddr:   unixStreamAddr,
			},
			err: ErrInvalidAddress,
		},
		{
			name: "v1MismatchTCPv4_TCPv6",
			header: &Header{
				Version:           1,
				Command:           PROXY,
				TransportProtocol: TCPv4,
				SourceAddr:        v6addr,
				DestinationAddr:   v4addr,
			},
			err: ErrInvalidAddress,
		},
		{
			name: "v1MismatchTCPv4_UDPv4",
			header: &Header{
				Version:           1,
				Command:           PROXY,
				TransportProtocol: TCPv4,
				SourceAddr:        v4UDPAddr,
				DestinationAddr:   v4addr,
			},
			err: ErrInvalidAddress,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.header.Format(); err == nil {
				t.Errorf("Header.Format() succeeded, want an error")
			} else if err != test.err {
				t.Errorf("Header.Format() = %q, want %q", err, test.err)
			}
		})
	}
}

func TestHeaderProxyFromAddrs(t *testing.T) {
	unspec := &Header{
		Version:           2,
		Command:           LOCAL,
		TransportProtocol: UNSPEC,
	}

	tests := []struct {
		name                 string
		version              byte
		sourceAddr, destAddr net.Addr
		expected             *Header
	}{
		{
			name: "TCPv4",
			sourceAddr: &net.TCPAddr{
				IP:   net.ParseIP(testSourceIPv4Addr),
				Port: 1000,
			},
			destAddr: &net.TCPAddr{
				IP:   net.ParseIP(testDestinationIPv4Addr),
				Port: 2000,
			},
			expected: &Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: TCPv4,
				SourceAddr: &net.TCPAddr{
					IP:   net.ParseIP(testSourceIPv4Addr),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP(testDestinationIPv4Addr),
					Port: 2000,
				},
			},
		},
		{
			name: "TCPv6",
			sourceAddr: &net.TCPAddr{
				IP:   net.ParseIP("fde7::372"),
				Port: 1000,
			},
			destAddr: &net.TCPAddr{
				IP:   net.ParseIP("fde7::1"),
				Port: 2000,
			},
			expected: &Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: TCPv6,
				SourceAddr: &net.TCPAddr{
					IP:   net.ParseIP("fde7::372"),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP("fde7::1"),
					Port: 2000,
				},
			},
		},
		{
			// Mixed family (v4 source, genuine v6 dest) must resolve to TCPv6, not
			// TCPv4. The old source-only logic chose TCPv4 here and then errored in
			// formatVersion1; see the both-ends family selection in header.go.
			name: "TCPv4SrcIPv6Dst",
			sourceAddr: &net.TCPAddr{
				IP:   net.ParseIP(testSourceIPv4Addr),
				Port: 1000,
			},
			destAddr: &net.TCPAddr{
				IP:   net.ParseIP("fde7::1"),
				Port: 2000,
			},
			expected: &Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: TCPv6,
				SourceAddr: &net.TCPAddr{
					IP:   net.ParseIP(testSourceIPv4Addr),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP("fde7::1"),
					Port: 2000,
				},
			},
		},
		{
			name: "UDPv4",
			sourceAddr: &net.UDPAddr{
				IP:   net.ParseIP(testSourceIPv4Addr),
				Port: 1000,
			},
			destAddr: &net.UDPAddr{
				IP:   net.ParseIP(testDestinationIPv4Addr),
				Port: 2000,
			},
			expected: &Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: UDPv4,
				SourceAddr: &net.TCPAddr{
					IP:   net.ParseIP(testSourceIPv4Addr),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP(testDestinationIPv4Addr),
					Port: 2000,
				},
			},
		},
		{
			name: "UDPv6",
			sourceAddr: &net.UDPAddr{
				IP:   net.ParseIP("fde7::372"),
				Port: 1000,
			},
			destAddr: &net.UDPAddr{
				IP:   net.ParseIP("fde7::1"),
				Port: 2000,
			},
			expected: &Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: UDPv6,
				SourceAddr: &net.TCPAddr{
					IP:   net.ParseIP("fde7::372"),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP("fde7::1"),
					Port: 2000,
				},
			},
		},
		{
			name: "UnixStream",
			sourceAddr: &net.UnixAddr{
				Net:  networkUnix,
				Name: testUnixSrcName,
			},
			destAddr: &net.UnixAddr{
				Net:  networkUnix,
				Name: testUnixDstName,
			},
			expected: &Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: UnixStream,
				SourceAddr: &net.UnixAddr{
					Net:  networkUnix,
					Name: testUnixSrcName,
				},
				DestinationAddr: &net.UnixAddr{
					Net:  networkUnix,
					Name: testUnixDstName,
				},
			},
		},
		{
			name: "UnixDatagram",
			sourceAddr: &net.UnixAddr{
				Net:  networkUnixgram,
				Name: testUnixSrcName,
			},
			destAddr: &net.UnixAddr{
				Net:  networkUnixgram,
				Name: testUnixDstName,
			},
			expected: &Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: UnixDatagram,
				SourceAddr: &net.UnixAddr{
					Net:  networkUnixgram,
					Name: testUnixSrcName,
				},
				DestinationAddr: &net.UnixAddr{
					Net:  networkUnixgram,
					Name: testUnixDstName,
				},
			},
		},
		{
			name:    "Version1",
			version: 1,
			sourceAddr: &net.TCPAddr{
				IP:   net.ParseIP(testSourceIPv4Addr),
				Port: 1000,
			},
			destAddr: &net.TCPAddr{
				IP:   net.ParseIP(testDestinationIPv4Addr),
				Port: 2000,
			},
			expected: &Header{
				Version:           1,
				Command:           PROXY,
				TransportProtocol: TCPv4,
				SourceAddr: &net.TCPAddr{
					IP:   net.ParseIP(testSourceIPv4Addr),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP(testDestinationIPv4Addr),
					Port: 2000,
				},
			},
		},
		{
			name: "TCPInvalidIP",
			sourceAddr: &net.TCPAddr{
				IP:   nil,
				Port: 1000,
			},
			destAddr: &net.TCPAddr{
				IP:   nil,
				Port: 2000,
			},
			expected: unspec,
		},
		{
			name: "UDPInvalidIP",
			sourceAddr: &net.UDPAddr{
				IP:   nil,
				Port: 1000,
			},
			destAddr: &net.UDPAddr{
				IP:   nil,
				Port: 2000,
			},
			expected: unspec,
		},
		{
			name: "TCPAddrTypeMismatch",
			sourceAddr: &net.TCPAddr{
				IP:   net.ParseIP(testSourceIPv4Addr),
				Port: 1000,
			},
			destAddr: &net.UDPAddr{
				IP:   net.ParseIP(testDestinationIPv4Addr),
				Port: 2000,
			},
			expected: unspec,
		},
		{
			name: "UDPAddrTypeMismatch",
			sourceAddr: &net.UDPAddr{
				IP:   net.ParseIP(testSourceIPv4Addr),
				Port: 1000,
			},
			destAddr: &net.TCPAddr{
				IP:   net.ParseIP(testDestinationIPv4Addr),
				Port: 2000,
			},
			expected: unspec,
		},
		{
			name: "UnixAddrTypeMismatch",
			sourceAddr: &net.UnixAddr{
				Net: networkUnix,
			},
			destAddr: &net.TCPAddr{
				IP:   net.ParseIP(testDestinationIPv4Addr),
				Port: 2000,
			},
			expected: unspec,
		},
		{
			// Stream source paired with a datagram destination is not a coherent
			// connection, so the header stays UNSPEC instead of adopting the
			// source's flavor.
			name: "UnixNetMismatch",
			sourceAddr: &net.UnixAddr{
				Net:  networkUnix,
				Name: testUnixSrcName,
			},
			destAddr: &net.UnixAddr{
				Net:  networkUnixgram,
				Name: testUnixDstName,
			},
			expected: unspec,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := HeaderProxyFromAddrs(tt.version, tt.sourceAddr, tt.destAddr)

			if !h.EqualsTo(tt.expected) {
				t.Errorf("expected %+v, actual %+v for source %+v and destination %+v", tt.expected, h, tt.sourceAddr, tt.destAddr)
			}
		})
	}
}
