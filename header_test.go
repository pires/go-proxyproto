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
	NO_PROTOCOL   = "There is no spoon"
	IP4_ADDR      = "127.0.0.1"
	IP6_ADDR      = "::1"
	IP6_LONG_ADDR = "1234:5678:9abc:def0:cafe:babe:dead:2bad"
	PORT          = 65533
	INVALID_PORT  = 99999
)

var (
	v4ip = net.ParseIP(IP4_ADDR).To4()
	v6ip = net.ParseIP(IP6_ADDR).To16()

	v4addr net.Addr = &net.TCPAddr{IP: v4ip, Port: PORT}
	v6addr net.Addr = &net.TCPAddr{IP: v6ip, Port: PORT}

	v4UDPAddr net.Addr = &net.UDPAddr{IP: v4ip, Port: PORT}
	v6UDPAddr net.Addr = &net.UDPAddr{IP: v6ip, Port: PORT}

	unixStreamAddr   net.Addr = &net.UnixAddr{Net: "unix", Name: "socket"}
	unixDatagramAddr net.Addr = &net.UnixAddr{Net: "unixgram", Name: "socket"}

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
					IP:   net.ParseIP("10.1.1.1"),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP("20.2.2.2"),
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
					IP:   net.ParseIP("10.1.1.1"),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP("20.2.2.2"),
					Port: 2000,
				},
			},
			&Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: TCPv4,
				SourceAddr: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP("20.2.2.2"),
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
					IP:   net.ParseIP("10.1.1.1"),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP("20.2.2.2"),
					Port: 2000,
				},
			},
			&Header{
				Version:           1,
				Command:           PROXY,
				TransportProtocol: TCPv4,
				SourceAddr: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP("20.2.2.2"),
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

// This is here just because of coveralls
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
					IP:   net.ParseIP("10.1.1.1"),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP("20.2.2.2"),
					Port: 2000,
				},
			},
			tcpSourceAddr: &net.TCPAddr{
				IP:   net.ParseIP("10.1.1.1"),
				Port: 1000,
			},
			tcpDestAddr: &net.TCPAddr{
				IP:   net.ParseIP("20.2.2.2"),
				Port: 2000,
			},
			ipSource:   net.ParseIP("10.1.1.1"),
			ipDest:     net.ParseIP("20.2.2.2"),
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
					IP:   net.ParseIP("10.1.1.1"),
					Port: 1000,
				},
				DestinationAddr: &net.UDPAddr{
					IP:   net.ParseIP("20.2.2.2"),
					Port: 2000,
				},
			},
			udpSourceAddr: &net.UDPAddr{
				IP:   net.ParseIP("10.1.1.1"),
				Port: 1000,
			},
			udpDestAddr: &net.UDPAddr{
				IP:   net.ParseIP("20.2.2.2"),
				Port: 2000,
			},
			ipSource:   net.ParseIP("10.1.1.1"),
			ipDest:     net.ParseIP("20.2.2.2"),
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
					Net:  "unix",
					Name: "src",
				},
				DestinationAddr: &net.UnixAddr{
					Net:  "unix",
					Name: "dst",
				},
			},
			unixSourceAddr: &net.UnixAddr{
				Net:  "unix",
				Name: "src",
			},
			unixDestAddr: &net.UnixAddr{
				Net:  "unix",
				Name: "dst",
			},
		},
		{
			name: "UnixDatagram",
			header: &Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: UnixDatagram,
				SourceAddr: &net.UnixAddr{
					Net:  "unix",
					Name: "src",
				},
				DestinationAddr: &net.UnixAddr{
					Net:  "unix",
					Name: "dst",
				},
			},
			unixSourceAddr: &net.UnixAddr{
				Net:  "unix",
				Name: "src",
			},
			unixDestAddr: &net.UnixAddr{
				Net:  "unix",
				Name: "dst",
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
					IP:   net.ParseIP("10.1.1.1"),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP("20.2.2.2"),
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
					IP:   net.ParseIP("10.1.1.1"),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP("20.2.2.2"),
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
			IP:   net.ParseIP("10.1.1.1"),
			Port: 1000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP("20.2.2.2"),
			Port: 2000,
		},
	}

	if _, err := validHeader.WriteTo(&buf); err != nil {
		t.Fatalf("shouldn't have thrown error %q", err.Error())
	}

	invalidHeader := &Header{
		SourceAddr: &net.TCPAddr{
			IP:   net.ParseIP("10.1.1.1"),
			Port: 1000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP("20.2.2.2"),
			Port: 2000,
		},
	}

	if _, err := invalidHeader.WriteTo(&buf); err == nil {
		t.Fatalf("should have thrown error %q", err.Error())
	}
}

func TestFormat(t *testing.T) {
	validHeader := &Header{
		Version:           1,
		Command:           PROXY,
		TransportProtocol: TCPv4,
		SourceAddr: &net.TCPAddr{
			IP:   net.ParseIP("10.1.1.1"),
			Port: 1000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP("20.2.2.2"),
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
				IP:   net.ParseIP("10.1.1.1"),
				Port: 1000,
			},
			destAddr: &net.TCPAddr{
				IP:   net.ParseIP("20.2.2.2"),
				Port: 2000,
			},
			expected: &Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: TCPv4,
				SourceAddr: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP("20.2.2.2"),
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
			name: "UDPv4",
			sourceAddr: &net.UDPAddr{
				IP:   net.ParseIP("10.1.1.1"),
				Port: 1000,
			},
			destAddr: &net.UDPAddr{
				IP:   net.ParseIP("20.2.2.2"),
				Port: 2000,
			},
			expected: &Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: UDPv4,
				SourceAddr: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP("20.2.2.2"),
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
				Net:  "unix",
				Name: "src",
			},
			destAddr: &net.UnixAddr{
				Net:  "unix",
				Name: "dst",
			},
			expected: &Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: UnixStream,
				SourceAddr: &net.UnixAddr{
					Net:  "unix",
					Name: "src",
				},
				DestinationAddr: &net.UnixAddr{
					Net:  "unix",
					Name: "dst",
				},
			},
		},
		{
			name: "UnixDatagram",
			sourceAddr: &net.UnixAddr{
				Net:  "unixgram",
				Name: "src",
			},
			destAddr: &net.UnixAddr{
				Net:  "unixgram",
				Name: "dst",
			},
			expected: &Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: UnixDatagram,
				SourceAddr: &net.UnixAddr{
					Net:  "unixgram",
					Name: "src",
				},
				DestinationAddr: &net.UnixAddr{
					Net:  "unixgram",
					Name: "dst",
				},
			},
		},
		{
			name:    "Version1",
			version: 1,
			sourceAddr: &net.TCPAddr{
				IP:   net.ParseIP("10.1.1.1"),
				Port: 1000,
			},
			destAddr: &net.TCPAddr{
				IP:   net.ParseIP("20.2.2.2"),
				Port: 2000,
			},
			expected: &Header{
				Version:           1,
				Command:           PROXY,
				TransportProtocol: TCPv4,
				SourceAddr: &net.TCPAddr{
					IP:   net.ParseIP("10.1.1.1"),
					Port: 1000,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP("20.2.2.2"),
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
				IP:   net.ParseIP("10.1.1.1"),
				Port: 1000,
			},
			destAddr: &net.UDPAddr{
				IP:   net.ParseIP("20.2.2.2"),
				Port: 2000,
			},
			expected: unspec,
		},
		{
			name: "UDPAddrTypeMismatch",
			sourceAddr: &net.UDPAddr{
				IP:   net.ParseIP("10.1.1.1"),
				Port: 1000,
			},
			destAddr: &net.TCPAddr{
				IP:   net.ParseIP("20.2.2.2"),
				Port: 2000,
			},
			expected: unspec,
		},
		{
			name: "UnixAddrTypeMismatch",
			sourceAddr: &net.UnixAddr{
				Net: "unix",
			},
			destAddr: &net.TCPAddr{
				IP:   net.ParseIP("20.2.2.2"),
				Port: 2000,
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
