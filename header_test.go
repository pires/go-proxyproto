package proxyproto

import (
	"bufio"
	"bytes"
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
)

type timeoutReader []byte

func (t *timeoutReader) Read([]byte) (int, error) {
	time.Sleep(500 * time.Millisecond)
	return 0, nil
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
