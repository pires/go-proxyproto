package proxyproto

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
	"testing"
)

var (
	TCP4AddressesAndPorts        = strings.Join([]string{IP4_ADDR, IP4_ADDR, strconv.Itoa(PORT), strconv.Itoa(PORT)}, SEPARATOR)
	TCP4AddressesAndInvalidPorts = strings.Join([]string{IP4_ADDR, IP4_ADDR, strconv.Itoa(INVALID_PORT), strconv.Itoa(INVALID_PORT)}, SEPARATOR)
	TCP6AddressesAndPorts        = strings.Join([]string{IP6_ADDR, IP6_ADDR, strconv.Itoa(PORT), strconv.Itoa(PORT)}, SEPARATOR)

	fixtureTCP4V1 = "PROXY TCP4 " + TCP4AddressesAndPorts + CRLF + "GET /"
	fixtureTCP6V1 = "PROXY TCP6 " + TCP6AddressesAndPorts + CRLF + "GET /"
)

var invalidParseV1Tests = []struct {
	reader        *bufio.Reader
	expectedError error
}{
	{
		newBufioReader([]byte("PROX")),
		ErrNoProxyProtocol,
	},
	{
		newBufioReader([]byte(NO_PROTOCOL)),
		ErrNoProxyProtocol,
	},
	{
		newBufioReader([]byte("PROXY \r\n")),
		ErrCantReadProtocolVersionAndCommand,
	},
	{
		newBufioReader([]byte("PROXY TCP4 " + TCP4AddressesAndPorts)),
		ErrCantReadProtocolVersionAndCommand,
	},
	{
		newBufioReader([]byte("PROXY TCP6 " + TCP4AddressesAndPorts + CRLF)),
		ErrInvalidAddress,
	},
	{
		newBufioReader([]byte("PROXY TCP4 " + TCP6AddressesAndPorts + CRLF)),
		ErrInvalidAddress,
	},
	// PROXY TCP IPv4
	{newBufioReader([]byte("PROXY TCP4 " + TCP4AddressesAndInvalidPorts + CRLF)),
		ErrInvalidPortNumber,
	},
}

func TestReadV1Invalid(t *testing.T) {
	for _, tt := range invalidParseV1Tests {
		if _, err := Read(tt.reader); err != tt.expectedError {
			t.Fatalf("TestReadV1Invalid: expected %s, actual %s", tt.expectedError, err.Error())
		}
	}
}

var validParseAndWriteV1Tests = []struct {
	reader         *bufio.Reader
	expectedHeader *Header
}{
	{
		bufio.NewReader(strings.NewReader(fixtureTCP4V1)),
		&Header{
			Version:            1,
			Command:            PROXY,
			TransportProtocol:  TCPv4,
			SourceAddress:      v4addr,
			DestinationAddress: v4addr,
			SourcePort:         PORT,
			DestinationPort:    PORT,
		},
	},
	{
		bufio.NewReader(strings.NewReader(fixtureTCP6V1)),
		&Header{
			Version:            1,
			Command:            PROXY,
			TransportProtocol:  TCPv6,
			SourceAddress:      v6addr,
			DestinationAddress: v6addr,
			SourcePort:         PORT,
			DestinationPort:    PORT,
		},
	},
}

func TestParseV1Valid(t *testing.T) {
	for _, tt := range validParseAndWriteV1Tests {
		header, err := Read(tt.reader)
		if err != nil {
			t.Fatal("TestParseV1Valid: unexpected error", err.Error())
		}
		if !header.EqualsTo(tt.expectedHeader) {
			t.Fatalf("TestParseV1Valid: expected %#v, actual %#v", tt.expectedHeader, header)
		}
	}
}

func TestWriteV1Valid(t *testing.T) {
	for _, tt := range validParseAndWriteV1Tests {
		var b bytes.Buffer
		w := bufio.NewWriter(&b)
		if _, err := tt.expectedHeader.WriteTo(w); err != nil {
			t.Fatal("TestWriteV1Valid: Unexpected error ", err)
		}
		w.Flush()

		// Read written bytes to validate written header
		r := bufio.NewReader(&b)
		newHeader, err := Read(r)
		if err != nil {
			t.Fatal("TestWriteV1Valid: Unexpected error ", err)
		}

		if !newHeader.EqualsTo(tt.expectedHeader) {
			t.Fatalf("TestWriteV1Valid: expected %#v, actual %#v", tt.expectedHeader, newHeader)
		}
	}
}
