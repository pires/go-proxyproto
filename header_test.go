package proxyproto

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

// Stuff to be used in both versions tests.

const (
	NO_PROTOCOL  = "There is no spoon"
	IP4_ADDR     = "127.0.0.1"
	IP6_ADDR     = "::1"
	PORT         = 65533
	INVALID_PORT = 99999
)

var (
	v4addr = net.ParseIP(IP4_ADDR).To4()
	v6addr = net.ParseIP(IP6_ADDR).To16()

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
				Version:            1,
				Command:            PROXY,
				TransportProtocol:  TCPv4,
				SourceAddress:      net.ParseIP("10.1.1.1"),
				SourcePort:         1000,
				DestinationAddress: net.ParseIP("20.2.2.2"),
				DestinationPort:    2000,
			},
			nil,
			false,
		},
		{
			&Header{
				Version:            1,
				Command:            PROXY,
				TransportProtocol:  TCPv4,
				SourceAddress:      net.ParseIP("10.1.1.1"),
				SourcePort:         1000,
				DestinationAddress: net.ParseIP("20.2.2.2"),
				DestinationPort:    2000,
			},
			&Header{
				Version:            2,
				Command:            PROXY,
				TransportProtocol:  TCPv4,
				SourceAddress:      net.ParseIP("10.1.1.1"),
				SourcePort:         1000,
				DestinationAddress: net.ParseIP("20.2.2.2"),
				DestinationPort:    2000,
			},
			false,
		},
		{
			&Header{
				Version:            1,
				Command:            PROXY,
				TransportProtocol:  TCPv4,
				SourceAddress:      net.ParseIP("10.1.1.1"),
				SourcePort:         1000,
				DestinationAddress: net.ParseIP("20.2.2.2"),
				DestinationPort:    2000,
			},
			&Header{
				Version:            1,
				Command:            PROXY,
				TransportProtocol:  TCPv4,
				SourceAddress:      net.ParseIP("10.1.1.1"),
				SourcePort:         1000,
				DestinationAddress: net.ParseIP("20.2.2.2"),
				DestinationPort:    2000,
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

func TestLocalAddr(t *testing.T) {
	var headers = []struct {
		header       *Header
		expectedAddr net.Addr
		expected     bool
	}{
		{
			&Header{
				Version:            1,
				Command:            PROXY,
				TransportProtocol:  TCPv4,
				SourceAddress:      net.ParseIP("10.1.1.1"),
				SourcePort:         1000,
				DestinationAddress: net.ParseIP("20.2.2.2"),
				DestinationPort:    2000,
			},
			&net.TCPAddr{
				IP:   net.ParseIP("20.2.2.2"),
				Port: 2000,
			},
			true,
		},
		{
			&Header{
				Version:            1,
				Command:            PROXY,
				TransportProtocol:  TCPv4,
				SourceAddress:      net.ParseIP("10.1.1.1"),
				SourcePort:         1000,
				DestinationAddress: net.ParseIP("20.2.2.2"),
				DestinationPort:    2000,
			},
			&net.TCPAddr{
				IP:   net.ParseIP("10.1.1.1"),
				Port: 1000,
			},
			false,
		},
	}

	for _, tt := range headers {
		actualAddr := tt.header.LocalAddr()
		if actual := actualAddr.String() == tt.expectedAddr.String(); actual != tt.expected {
			t.Fatalf("expected %t, actual %t for expectedAddr %+v and actualAddr %+v", tt.expected, actual, tt.expectedAddr, actualAddr)
		}
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
				Version:            1,
				Command:            PROXY,
				TransportProtocol:  TCPv4,
				SourceAddress:      net.ParseIP("10.1.1.1"),
				SourcePort:         1000,
				DestinationAddress: net.ParseIP("20.2.2.2"),
				DestinationPort:    2000,
			},
			tlvs: []TLV{{
				Type:   PP2_TYPE_AUTHORITY,
				Length: 11,
				Value:  []byte("example.org"),
			}},
		},
		{
			name: "add wrong length",
			header: &Header{
				Version:            1,
				Command:            PROXY,
				TransportProtocol:  TCPv4,
				SourceAddress:      net.ParseIP("10.1.1.1"),
				SourcePort:         1000,
				DestinationAddress: net.ParseIP("20.2.2.2"),
				DestinationPort:    2000,
			},
			tlvs: []TLV{{
				Type:   PP2_TYPE_AUTHORITY,
				Length: 1,
				Value:  []byte("example.org"),
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

func TestRemoteAddr(t *testing.T) {
	var headers = []struct {
		header       *Header
		expectedAddr net.Addr
		expected     bool
	}{
		{
			&Header{
				Version:            1,
				Command:            PROXY,
				TransportProtocol:  TCPv4,
				SourceAddress:      net.ParseIP("10.1.1.1"),
				SourcePort:         1000,
				DestinationAddress: net.ParseIP("20.2.2.2"),
				DestinationPort:    2000,
			},
			&net.TCPAddr{
				IP:   net.ParseIP("20.2.2.2"),
				Port: 2000,
			},
			true,
		},
		{
			&Header{
				Version:            1,
				Command:            PROXY,
				TransportProtocol:  TCPv4,
				SourceAddress:      net.ParseIP("10.1.1.1"),
				SourcePort:         1000,
				DestinationAddress: net.ParseIP("20.2.2.2"),
				DestinationPort:    2000,
			},
			&net.TCPAddr{
				IP:   net.ParseIP("10.1.1.1"),
				Port: 1000,
			},
			false,
		},
	}

	for _, tt := range headers {
		actualAddr := tt.header.LocalAddr()
		if actual := actualAddr.String() == tt.expectedAddr.String(); actual != tt.expected {
			t.Fatalf("expected %t, actual %t for expectedAddr %+v and actualAddr %+v", tt.expected, actual, tt.expectedAddr, actualAddr)
		}
	}
}

func TestWriteTo(t *testing.T) {
	var buf bytes.Buffer

	validHeader := &Header{
		Version:            1,
		Command:            PROXY,
		TransportProtocol:  TCPv4,
		SourceAddress:      net.ParseIP("10.1.1.1"),
		SourcePort:         1000,
		DestinationAddress: net.ParseIP("20.2.2.2"),
		DestinationPort:    2000,
	}

	if _, err := validHeader.WriteTo(&buf); err != nil {
		t.Fatalf("shouldn't have thrown error %q", err.Error())
	}

	invalidHeader := &Header{
		SourceAddress:      net.ParseIP("10.1.1.1"),
		SourcePort:         1000,
		DestinationAddress: net.ParseIP("20.2.2.2"),
		DestinationPort:    2000,
	}

	if _, err := invalidHeader.WriteTo(&buf); err == nil {
		t.Fatalf("should have thrown error %q", err.Error())
	}
}

func TestFormat(t *testing.T) {
	validHeader := &Header{
		Version:            1,
		Command:            PROXY,
		TransportProtocol:  TCPv4,
		SourceAddress:      net.ParseIP("10.1.1.1"),
		SourcePort:         1000,
		DestinationAddress: net.ParseIP("20.2.2.2"),
		DestinationPort:    2000,
	}

	if _, err := validHeader.Format(); err != nil {
		t.Fatalf("shouldn't have thrown error %q", err.Error())
	}

	invalidHeader := &Header{
		Version:            3,
		Command:            PROXY,
		TransportProtocol:  TCPv4,
		SourceAddress:      net.ParseIP("10.1.1.1"),
		SourcePort:         1000,
		DestinationAddress: net.ParseIP("20.2.2.2"),
		DestinationPort:    2000,
	}

	if _, err := invalidHeader.Format(); err == nil {
		t.Fatalf("should have thrown error %q", err.Error())
	} else {
		if err != ErrUnknownProxyProtocolVersion {
			t.Fatalf("expected %q, actual %q", ErrUnknownProxyProtocolVersion.Error(), err.Error())
		}
	}
}

func TestHeaderProxyFromAddrs(t *testing.T) {
	unspec := &Header{
		Version:           2,
		Command:           PROXY,
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
				Version:            2,
				Command:            PROXY,
				TransportProtocol:  TCPv4,
				SourceAddress:      net.ParseIP("10.1.1.1"),
				SourcePort:         1000,
				DestinationAddress: net.ParseIP("20.2.2.2"),
				DestinationPort:    2000,
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
				Version:            2,
				Command:            PROXY,
				TransportProtocol:  TCPv6,
				SourceAddress:      net.ParseIP("fde7::372"),
				SourcePort:         1000,
				DestinationAddress: net.ParseIP("fde7::1"),
				DestinationPort:    2000,
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
				Version:            2,
				Command:            PROXY,
				TransportProtocol:  UDPv4,
				SourceAddress:      net.ParseIP("10.1.1.1"),
				SourcePort:         1000,
				DestinationAddress: net.ParseIP("20.2.2.2"),
				DestinationPort:    2000,
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
				Version:            2,
				Command:            PROXY,
				TransportProtocol:  UDPv6,
				SourceAddress:      net.ParseIP("fde7::372"),
				SourcePort:         1000,
				DestinationAddress: net.ParseIP("fde7::1"),
				DestinationPort:    2000,
			},
		},
		{
			name: "UnixStream",
			sourceAddr: &net.UnixAddr{
				Net: "unix",
			},
			destAddr: &net.UnixAddr{
				Net: "unix",
			},
			expected: &Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: UnixStream,
			},
		},
		{
			name: "UnixDatagram",
			sourceAddr: &net.UnixAddr{
				Net: "unixgram",
			},
			destAddr: &net.UnixAddr{
				Net: "unixgram",
			},
			expected: &Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: UnixDatagram,
			},
		},
		{
			name:    "Version1",
			version: 1,
			sourceAddr: &net.UnixAddr{
				Net: "unix",
			},
			destAddr: &net.UnixAddr{
				Net: "unix",
			},
			expected: &Header{
				Version:           1,
				Command:           PROXY,
				TransportProtocol: UnixStream,
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
