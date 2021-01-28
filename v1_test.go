package proxyproto

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
	"testing"
)

var (
	IPv4AddressesAndPorts        = strings.Join([]string{IP4_ADDR, IP4_ADDR, strconv.Itoa(PORT), strconv.Itoa(PORT)}, separator)
	IPv4AddressesAndInvalidPorts = strings.Join([]string{IP4_ADDR, IP4_ADDR, strconv.Itoa(INVALID_PORT), strconv.Itoa(INVALID_PORT)}, separator)
	IPv6AddressesAndPorts        = strings.Join([]string{IP6_ADDR, IP6_ADDR, strconv.Itoa(PORT), strconv.Itoa(PORT)}, separator)

	fixtureTCP4V1 = "PROXY TCP4 " + IPv4AddressesAndPorts + crlf + "GET /"
	fixtureTCP6V1 = "PROXY TCP6 " + IPv6AddressesAndPorts + crlf + "GET /"

	fixtureUnknown              = "PROXY UNKNOWN" + crlf
	fixtureUnknownWithAddresses = "PROXY UNKNOWN " + IPv4AddressesAndInvalidPorts + crlf
)

var invalidParseV1Tests = []struct {
	desc          string
	reader        *bufio.Reader
	expectedError error
}{
	{
		desc:          "no signature",
		reader:        newBufioReader([]byte(NO_PROTOCOL)),
		expectedError: ErrNoProxyProtocol,
	},
	{
		desc:          "prox",
		reader:        newBufioReader([]byte("PROX")),
		expectedError: ErrNoProxyProtocol,
	},
	{
		desc:          "proxy lf",
		reader:        newBufioReader([]byte("PROXY \n")),
		expectedError: ErrLineMustEndWithCrlf,
	},
	{
		desc:          "proxy crlf",
		reader:        newBufioReader([]byte("PROXY " + crlf)),
		expectedError: ErrCantReadAddressFamilyAndProtocol,
	},
	{
		desc:          "proxy no space crlf",
		reader:        newBufioReader([]byte("PROXY" + crlf)),
		expectedError: ErrCantReadAddressFamilyAndProtocol,
	},
	{
		desc:          "proxy something crlf",
		reader:        newBufioReader([]byte("PROXY SOMETHING" + crlf)),
		expectedError: ErrCantReadAddressFamilyAndProtocol,
	},
	{
		desc:          "incomplete signature TCP4",
		reader:        newBufioReader([]byte("PROXY TCP4 " + IPv4AddressesAndPorts)),
		expectedError: ErrLineMustEndWithCrlf,
	},
	{
		desc:          "TCP6 with IPv4 addresses",
		reader:        newBufioReader([]byte("PROXY TCP6 " + IPv4AddressesAndPorts + crlf)),
		expectedError: ErrInvalidAddress,
	},
	{
		desc:          "TCP4 with IPv6 addresses",
		reader:        newBufioReader([]byte("PROXY TCP4 " + IPv6AddressesAndPorts + crlf)),
		expectedError: ErrInvalidAddress,
	},
	{
		desc:          "TCP4 with invalid port",
		reader:        newBufioReader([]byte("PROXY TCP4 " + IPv4AddressesAndInvalidPorts + crlf)),
		expectedError: ErrInvalidPortNumber,
	},
}

func TestReadV1Invalid(t *testing.T) {
	for _, tt := range invalidParseV1Tests {
		t.Run(tt.desc, func(t *testing.T) {
			if _, err := Read(tt.reader); err != tt.expectedError {
				t.Fatalf("expected %s, actual %s", tt.expectedError, err.Error())
			}
		})
	}
}

var validParseAndWriteV1Tests = []struct {
	desc           string
	reader         *bufio.Reader
	expectedHeader *Header
}{
	{
		desc:   "TCP4",
		reader: bufio.NewReader(strings.NewReader(fixtureTCP4V1)),
		expectedHeader: &Header{
			Version:           1,
			Command:           PROXY,
			TransportProtocol: TCPv4,
			SourceAddr:        v4addr,
			DestinationAddr:   v4addr,
		},
	},
	{
		desc:   "TCP6",
		reader: bufio.NewReader(strings.NewReader(fixtureTCP6V1)),
		expectedHeader: &Header{
			Version:           1,
			Command:           PROXY,
			TransportProtocol: TCPv6,
			SourceAddr:        v6addr,
			DestinationAddr:   v6addr,
		},
	},
	{
		desc:   "unknown",
		reader: bufio.NewReader(strings.NewReader(fixtureUnknown)),
		expectedHeader: &Header{
			Version:           1,
			Command:           LOCAL,
			TransportProtocol: UNSPEC,
			SourceAddr:        nil,
			DestinationAddr:   nil,
		},
	},
	{
		desc:   "unknown with addresses and ports",
		reader: bufio.NewReader(strings.NewReader(fixtureUnknownWithAddresses)),
		expectedHeader: &Header{
			Version:           1,
			Command:           LOCAL,
			TransportProtocol: UNSPEC,
			SourceAddr:        nil,
			DestinationAddr:   nil,
		},
	},
}

func TestParseV1Valid(t *testing.T) {
	for _, tt := range validParseAndWriteV1Tests {
		t.Run(tt.desc, func(t *testing.T) {
			header, err := Read(tt.reader)
			if err != nil {
				t.Fatal("unexpected error", err.Error())
			}
			if !header.EqualsTo(tt.expectedHeader) {
				t.Fatalf("expected %#v, actual %#v", tt.expectedHeader, header)
			}
		})
	}
}

func TestWriteV1Valid(t *testing.T) {
	for _, tt := range validParseAndWriteV1Tests {
		t.Run(tt.desc, func(t *testing.T) {
			var b bytes.Buffer
			w := bufio.NewWriter(&b)
			if _, err := tt.expectedHeader.WriteTo(w); err != nil {
				t.Fatal("unexpected error ", err)
			}
			w.Flush()

			// Read written bytes to validate written header
			r := bufio.NewReader(&b)
			newHeader, err := Read(r)
			if err != nil {
				t.Fatal("unexpected error ", err)
			}

			if !newHeader.EqualsTo(tt.expectedHeader) {
				t.Fatalf("expected %#v, actual %#v", tt.expectedHeader, newHeader)
			}
		})
	}
}
