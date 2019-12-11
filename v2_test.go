package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"math/rand"
	"reflect"
	"testing"
)

var (
	invalidRune = byte('\x99')

	// Lengths to use in tests
	lengthPadded = uint16(84)

	lengthEmptyBytes = func() []byte {
		a := make([]byte, 2)
		binary.BigEndian.PutUint16(a, 0)
		return a
	}()
	lengthPaddedBytes = func() []byte {
		a := make([]byte, 2)
		binary.BigEndian.PutUint16(a, lengthPadded)
		return a
	}()

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
	fixtureIPv4Address  = append(addressesIPv4, ports...)
	fixtureIPv4V2       = append(lengthV4Bytes, fixtureIPv4Address...)
	fixtureIPv4V2Padded = append(append(lengthPaddedBytes, fixtureIPv4Address...), make([]byte, lengthPadded-lengthV4)...)
	fixtureIPv6Address  = append(addressesIPv6, ports...)
	fixtureIPv6V2       = append(lengthV6Bytes, fixtureIPv6Address...)
	fixtureIPv6V2Padded = append(append(lengthPaddedBytes, fixtureIPv6Address...), make([]byte, lengthPadded-lengthV6)...)
	fixtureTLV          = func() []byte {
		tlv := make([]byte, 2+rand.Intn(1<<12)) // Not enough to overflow, at least size two
		rand.Read(tlv)
		return tlv
	}()
	fixtureIPv4V2TLV = fixtureWithTLV(lengthV4Bytes, fixtureIPv4Address, fixtureTLV)
	fixtureIPv6V2TLV = fixtureWithTLV(lengthV6Bytes, fixtureIPv6Address, fixtureTLV)

	// Arbitrary bytes following proxy bytes
	arbitraryTailBytes = []byte{'\x99', '\x97', '\x98'}
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
		newBufioReader(append(append(append(SIGV2, PROXY, TCPv4), lengthEmptyBytes...), fixtureIPv6Address...)),
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
			t.Fatalf("TestParseV2Invalid: expected %s, actual %s", tt.expectedError, err.Error())
		}
	}
}

var validParseAndWriteV2Tests = []struct {
	reader         *bufio.Reader
	expectedHeader *Header
}{
	// LOCAL
	{
		newBufioReader(append(append(SIGV2, LOCAL, TCPv4), fixtureIPv4V2...)),
		&Header{
			Version:            2,
			Command:            LOCAL,
			TransportProtocol:  TCPv4,
			SourceAddress:      v4addr,
			DestinationAddress: v4addr,
			SourcePort:         PORT,
			DestinationPort:    PORT,
		},
	},
	// PROXY TCP IPv4
	{
		newBufioReader(append(append(SIGV2, PROXY, TCPv4), fixtureIPv4V2...)),
		&Header{
			Version:            2,
			Command:            PROXY,
			TransportProtocol:  TCPv4,
			SourceAddress:      v4addr,
			DestinationAddress: v4addr,
			SourcePort:         PORT,
			DestinationPort:    PORT,
		},
	},
	// PROXY TCP IPv6
	{
		newBufioReader(append(append(SIGV2, PROXY, TCPv6), fixtureIPv6V2...)),
		&Header{
			Version:            2,
			Command:            PROXY,
			TransportProtocol:  TCPv6,
			SourceAddress:      v6addr,
			DestinationAddress: v6addr,
			SourcePort:         PORT,
			DestinationPort:    PORT,
		},
	},
	// PROXY TCP IPv4 with TLV
	{
		newBufioReader(append(append(SIGV2, PROXY, TCPv4), fixtureIPv4V2TLV...)),
		&Header{
			Version:            2,
			Command:            PROXY,
			TransportProtocol:  TCPv4,
			SourceAddress:      v4addr,
			DestinationAddress: v4addr,
			SourcePort:         PORT,
			DestinationPort:    PORT,
			rawTLVs:            fixtureTLV,
		},
	},
	// PROXY TCP IPv6 with TLV
	{
		newBufioReader(append(append(SIGV2, PROXY, TCPv6), fixtureIPv6V2TLV...)),
		&Header{
			Version:            2,
			Command:            PROXY,
			TransportProtocol:  TCPv6,
			SourceAddress:      v6addr,
			DestinationAddress: v6addr,
			SourcePort:         PORT,
			DestinationPort:    PORT,
			rawTLVs:            fixtureTLV,
		},
	},
	// PROXY UDP IPv4
	{
		newBufioReader(append(append(SIGV2, PROXY, UDPv4), fixtureIPv4V2...)),
		&Header{
			Version:            2,
			Command:            PROXY,
			TransportProtocol:  UDPv4,
			SourceAddress:      v4addr,
			DestinationAddress: v4addr,
			SourcePort:         PORT,
			DestinationPort:    PORT,
		},
	},
	// PROXY UDP IPv6
	{
		newBufioReader(append(append(SIGV2, PROXY, UDPv6), fixtureIPv6V2...)),
		&Header{
			Version:            2,
			Command:            PROXY,
			TransportProtocol:  UDPv6,
			SourceAddress:      v6addr,
			DestinationAddress: v6addr,
			SourcePort:         PORT,
			DestinationPort:    PORT,
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
		if !header.EqualsTo(tt.expectedHeader) {
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

		if !newHeader.EqualsTo(tt.expectedHeader) {
			t.Fatalf("TestWriteVersion2: expected %#v, actual %#v", tt.expectedHeader, newHeader)
		}
	}
}

var validParseV2PaddedTests = []struct {
	value          []byte
	expectedHeader *Header
}{
	// PROXY TCP IPv4
	{
		append(append(SIGV2, PROXY, TCPv4), fixtureIPv4V2Padded...),
		&Header{
			Version:            2,
			Command:            PROXY,
			TransportProtocol:  TCPv4,
			SourceAddress:      v4addr,
			DestinationAddress: v4addr,
			SourcePort:         PORT,
			DestinationPort:    PORT,
			rawTLVs:            make([]byte, lengthPadded-lengthV4),
		},
	},
	// PROXY TCP IPv6
	{
		append(append(SIGV2, PROXY, TCPv6), fixtureIPv6V2Padded...),
		&Header{
			Version:            2,
			Command:            PROXY,
			TransportProtocol:  TCPv6,
			SourceAddress:      v6addr,
			DestinationAddress: v6addr,
			SourcePort:         PORT,
			DestinationPort:    PORT,
			rawTLVs:            make([]byte, lengthPadded-lengthV6),
		},
	},
	// PROXY UDP IPv4
	{
		append(append(SIGV2, PROXY, UDPv4), fixtureIPv4V2Padded...),
		&Header{
			Version:            2,
			Command:            PROXY,
			TransportProtocol:  UDPv4,
			SourceAddress:      v4addr,
			DestinationAddress: v4addr,
			SourcePort:         PORT,
			DestinationPort:    PORT,
			rawTLVs:            make([]byte, lengthPadded-lengthV4),
		},
	},
	// PROXY UDP IPv6
	{
		append(append(SIGV2, PROXY, UDPv6), fixtureIPv6V2Padded...),
		&Header{
			Version:            2,
			Command:            PROXY,
			TransportProtocol:  UDPv6,
			SourceAddress:      v6addr,
			DestinationAddress: v6addr,
			SourcePort:         PORT,
			DestinationPort:    PORT,
			rawTLVs:            make([]byte, lengthPadded-lengthV6),
		},
	},
}

func TestParseV2Padded(t *testing.T) {
	for _, tt := range validParseV2PaddedTests {
		reader := newBufioReader(append(tt.value, arbitraryTailBytes...))

		newHeader, err := Read(reader)
		if err != nil {
			t.Fatal("TestParseV2Padded: Unexpected error ", err)
		}
		if !newHeader.EqualsTo(tt.expectedHeader) {
			t.Fatalf("TestParseV2Padded: expected %#v, actual %#v", tt.expectedHeader, newHeader)
		}

		// Check that remaining padding bytes have been flushed
		nextBytes, err := reader.Peek(len(arbitraryTailBytes))
		if err != nil {
			t.Fatal("TestParseV2Padded: Unexpected error ", err)
		}
		if !reflect.DeepEqual(nextBytes, arbitraryTailBytes) {
			t.Fatalf("TestParseV2Padded: expected %#v, actual %#v", arbitraryTailBytes, nextBytes)
		}
	}
}

func TestV2EqualsToTLV(t *testing.T) {
	eHdr := &Header{
		Version:            2,
		Command:            PROXY,
		TransportProtocol:  TCPv4,
		SourceAddress:      v4addr,
		DestinationAddress: v4addr,
		SourcePort:         PORT,
		DestinationPort:    PORT,
	}
	hdr, err := Read(newBufioReader(append(append(SIGV2, PROXY, TCPv4), fixtureIPv4V2TLV...)))
	if err != nil {
		t.Fatal("TestV2EqualsToTLV: Unexpected error ", err)
	}
	if eHdr.EqualsTo(hdr) {
		t.Fatalf("TestV2EqualsToTLV: Unexpectedly equal created: %#v, parsed: %#v", eHdr, hdr)
	}
	eHdr.rawTLVs = fixtureTLV[:]

	if !eHdr.EqualsTo(hdr) {
		t.Fatalf("TestV2EqualsToTLV: Unexpectedly unequal after tlv copy created: %#v, parsed: %#v", eHdr, hdr)
	}

	eHdr.rawTLVs[0] = eHdr.rawTLVs[0] + 1
	if eHdr.EqualsTo(hdr) {
		t.Fatalf("TestV2EqualsToTLV: Unexpectedly equal after changing tlv created: %#v, parsed: %#v", eHdr, hdr)
	}
}

var tlvFormatTests = []*Header{
	// PROXY TCP IPv4
	&Header{
		Version:            2,
		Command:            PROXY,
		TransportProtocol:  TCPv4,
		SourceAddress:      v4addr,
		DestinationAddress: v4addr,
		SourcePort:         PORT,
		DestinationPort:    PORT,
		rawTLVs:            make([]byte, 1<<16),
	},
	// PROXY TCP IPv6
	&Header{
		Version:            2,
		Command:            PROXY,
		TransportProtocol:  TCPv6,
		SourceAddress:      v6addr,
		DestinationAddress: v6addr,
		SourcePort:         PORT,
		DestinationPort:    PORT,
		rawTLVs:            make([]byte, 1<<16),
	},
	// PROXY UDP IPv4
	&Header{
		Version:            2,
		Command:            PROXY,
		TransportProtocol:  UDPv4,
		SourceAddress:      v4addr,
		DestinationAddress: v4addr,
		SourcePort:         PORT,
		DestinationPort:    PORT,
		rawTLVs:            make([]byte, 1<<16),
	},
	// PROXY UDP IPv6
	&Header{
		Version:            2,
		Command:            PROXY,
		TransportProtocol:  UDPv6,
		SourceAddress:      v6addr,
		DestinationAddress: v6addr,
		SourcePort:         PORT,
		DestinationPort:    PORT,
		rawTLVs:            make([]byte, 1<<16),
	},
}

func TestV2TLVFormatTooLargeTLV(t *testing.T) {
	for _, tt := range tlvFormatTests {
		if _, err := tt.Format(); err != errUint16Overflow {
			t.Fatalf("TestV2TLVFormatTooLargeTLV: missing or expected error when formatting too-large TLV %#v", err)
		}
	}
}

func newBufioReader(b []byte) *bufio.Reader {
	return bufio.NewReader(bytes.NewReader(b))
}

func fixtureWithTLV(cur []byte, addr []byte, tlv []byte) []byte {
	tlen, err := addTLVLen(cur, len(tlv))
	if err != nil {
		panic(err)
	}
	return append(append(tlen, addr...), tlv...)
}
