package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"
)

var (
	invalidRune = byte('\x99')

	// If life gives you lemons, make mojitos
	portBytes = func() []byte {
		a := make([]byte, 2)
		binary.BigEndian.PutUint16(a, PORT)
		return a
	}()

	// Tests don't care if source and destination addresses and ports are the same
	addressesIPv4 = append(v4addr.To4(), v4addr.To4()...)
	addressesIPv6 = append(v6addr.To16(), v6addr.To16()...)
	ports         = append(portBytes, portBytes...)

	// Fixtures to use in tests
	fixtureIPv4Address = append(addressesIPv4, ports...)
	fixtureIPv4V2      = append(lengthV4Bytes, fixtureIPv4Address...)
	fixtureIPv6Address = append(addressesIPv6, ports...)
	fixtureIPv6V2      = append(lengthV6Bytes, fixtureIPv6Address...)
)

var invalidParseV2Tests = []struct {
	reader        *bufio.Reader
	expectedError error
}{
	{
		newBufioReader(SIGV2[2:]),
		ErrNoProxyProtocol,
	},
	{
		newBufioReader([]byte(NO_PROTOCOL)),
		ErrNoProxyProtocol,
	},
	{
		newBufioReader(SIGV2),
		ErrCantReadProtocolVersionAndCommand,
	},
	{
		newBufioReader(append(SIGV2, invalidRune)),
		ErrUnsupportedProtocolVersionAndCommand,
	},
	{
		newBufioReader(append(SIGV2, PROXY)),
		ErrCantReadAddressFamilyAndProtocol,
	},
	{
		newBufioReader(append(SIGV2, PROXY, invalidRune)),
		ErrUnsupportedAddressFamilyAndProtocol,
	},
	{
		newBufioReader(append(SIGV2, PROXY, TCPv4)),
		ErrCantReadLength,
	},
	{
		newBufioReader(append(SIGV2, PROXY, TCPv4, invalidRune)),
		ErrCantReadLength,
	},
	{
		newBufioReader(append(append(SIGV2, PROXY, TCPv4), lengthV4Bytes...)),
		ErrInvalidLength,
	},
	{
		newBufioReader(append(append(SIGV2, PROXY, TCPv6), lengthV6Bytes...)),
		ErrInvalidLength,
	},
	{
		newBufioReader(append(append(append(SIGV2, PROXY, TCPv4), lengthV6Bytes...), fixtureIPv6Address...)),
		ErrInvalidLength,
	},
	{
		newBufioReader(append(append(append(SIGV2, PROXY, TCPv6), lengthV6Bytes...), fixtureIPv4Address...)),
		ErrInvalidLength,
	},
}

func TestParseV2Invalid(t *testing.T) {
	for _, tt := range invalidParseV2Tests {
		if _, err := Read(tt.reader); err != tt.expectedError {
			t.Fatalf("TestParseV2Invalid: expected %s, actual %s", tt.expectedError, err)
		}
	}
}

var validParseAndWriteV2Tests = []struct {
	reader         *bufio.Reader
	expectedHeader *v1header
}{
	// LOCAL
	{
		newBufioReader(append(SIGV2, LOCAL)),
		&v1header{
			Version: 2,
			command: LOCAL,
		},
	},
	// PROXY TCP IPv4
	{
		newBufioReader(append(append(SIGV2, PROXY, TCPv4), fixtureIPv4V2...)),
		&v1header{
			Version:            2,
			command:            PROXY,
			transportProtocol:  TCPv4,
			sourceAddress:      v4addr,
			destinationAddress: v4addr,
			sourcePort:         PORT,
			destinationPort:    PORT,
		},
	},
	// PROXY TCP IPv6
	{
		newBufioReader(append(append(SIGV2, PROXY, TCPv6), fixtureIPv6V2...)),
		&v1header{
			Version:            2,
			command:            PROXY,
			transportProtocol:  TCPv6,
			sourceAddress:      v6addr,
			destinationAddress: v6addr,
			sourcePort:         PORT,
			destinationPort:    PORT,
		},
	},
	// PROXY UDP IPv4
	{
		newBufioReader(append(append(SIGV2, PROXY, UDPv4), fixtureIPv4V2...)),
		&v1header{
			Version:            2,
			command:            PROXY,
			transportProtocol:  UDPv4,
			sourceAddress:      v4addr,
			destinationAddress: v4addr,
			sourcePort:         PORT,
			destinationPort:    PORT,
		},
	},
	// PROXY UDP IPv6
	{
		newBufioReader(append(append(SIGV2, PROXY, UDPv6), fixtureIPv6V2...)),
		&v1header{
			Version:            2,
			command:            PROXY,
			transportProtocol:  UDPv6,
			sourceAddress:      v6addr,
			destinationAddress: v6addr,
			sourcePort:         PORT,
			destinationPort:    PORT,
		},
	},
	// TODO add tests for Unix stream and datagram
}

func TestParseV2Valid(t *testing.T) {
	for _, tt := range validParseAndWriteV2Tests {
		header, err := Read(tt.reader)
		if err != nil {
			t.Fatal("TestParseV2Valid: unexpected error", err.Error())
		}
		if !header.EqualTo(tt.expectedHeader) {
			t.Fatalf("TestParseV2Valid: expected %#v, actual %#v", tt.expectedHeader, header)
		}
	}
}

func TestWriteV2Valid(t *testing.T) {
	for _, tt := range validParseAndWriteV2Tests {
		var b bytes.Buffer
		w := bufio.NewWriter(&b)
		if _, err := tt.expectedHeader.WriteTo(w); err != nil {
			t.Fatal("TestWriteVersion2: Unexpected error ", err)
		}
		w.Flush()

		// Read written bytes to validate written header
		r := bufio.NewReader(&b)
		newHeader, err := Read(r)
		if err != nil {
			t.Fatal("TestWriteVersion2: Unexpected error ", err)
		}

		if !newHeader.EqualTo(tt.expectedHeader) {
			t.Fatalf("TestWriteVersion2: expected %#v, actual %#v", tt.expectedHeader, newHeader)
		}
	}
}

func newBufioReader(b []byte) *bufio.Reader {
	return bufio.NewReader(bytes.NewReader(b))
}
