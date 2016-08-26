package proxyproto

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
	"testing"
)

var (
	TCP4AddressesAndPorts = strings.Join([]string{IP4_ADDR, IP4_ADDR, strconv.Itoa(PORT), strconv.Itoa(PORT)}, SEPARATOR)
	TCP6AddressesAndPorts = strings.Join([]string{IP6_ADDR, IP6_ADDR, strconv.Itoa(PORT), strconv.Itoa(PORT)}, SEPARATOR)

	fixtureTCP4V1 = "PROXY TCP4 " + TCP4AddressesAndPorts + CRLF + "GET /"
	fixtureTCP6V1 = "PROXY TCP6 " + TCP6AddressesAndPorts + CRLF + "GET /"
)

var invalidParseV1Tests = []struct {
	reader        *bufio.Reader
	expectedError error
}{
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
		ErrInetFamilyDoesntMatchProtocol,
	},
	{
		newBufioReader([]byte("PROXY TCP4 " + TCP6AddressesAndPorts + CRLF)),
		ErrInetFamilyDoesntMatchProtocol,
	},
}

func TestParseV1Invalid(t *testing.T) {
	for _, tt := range invalidParseV1Tests {
		if _, err := Read(tt.reader); err != tt.expectedError {
			t.Fatalf("TestParseV1Invalid: expected %s, actual %s", tt.expectedError, err)
		}
	}
}

var validParseV1Tests = []struct {
	reader         *bufio.Reader
	expectedHeader *Header
}{
	{
		bufio.NewReader(strings.NewReader(fixtureTCP4V1)),
		&Header{
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
	for _, tt := range validParseV1Tests {
		header, err := Read(tt.reader)
		if err != nil {
			t.Fatal("TestParseV1Valid: unexpected error", err.Error())
		}
		if !header.EqualTo(tt.expectedHeader) {
			t.Fatalf("TestParseV1Valid: expected %#v, actual %#v", tt.expectedHeader, header)
		}
	}
}

func TestWriteVersion1(t *testing.T) {
	// Build valid header
	reader := bufio.NewReader(strings.NewReader(fixtureTCP6V1))
	if header, err := Read(reader); err != nil {
		t.Fatal("TestWriteVersion1: Unexpected error ", err)
	} else {
		var b bytes.Buffer
		w := bufio.NewWriter(&b)
		if _, err := header.WriteTo(w); err != nil {
			t.Fatal("TestWriteVersion1: Unexpected error ", err)
		}
		// Read written bytes to validate written header
		reader = bufio.NewReader(strings.NewReader(fixtureTCP6V1))
		if _, err := Read(reader); err != nil {
			t.Fatal("TestWriteVersion1: Unexpected error ", err)
		}
	}
}
