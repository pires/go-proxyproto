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

	unixBytes = pad([]byte("socket"), 108)

	// Tests don't care if source and destination addresses and ports are the same
	addressesIPv4 = append(v4ip.To4(), v4ip.To4()...)
	addressesIPv6 = append(v6ip.To16(), v6ip.To16()...)
	ports         = append(portBytes, portBytes...)

	// Fixtures to use in tests
	fixtureIPv4Address  = append(addressesIPv4, ports...)
	fixtureIPv4V2       = append(lengthV4Bytes, fixtureIPv4Address...)
	fixtureIPv4V2Padded = append(append(lengthPaddedBytes, fixtureIPv4Address...), make([]byte, lengthPadded-lengthV4)...)
	fixtureIPv6Address  = append(addressesIPv6, ports...)
	fixtureIPv6V2       = append(lengthV6Bytes, fixtureIPv6Address...)
	fixtureIPv6V2Padded = append(append(lengthPaddedBytes, fixtureIPv6Address...), make([]byte, lengthPadded-lengthV6)...)
	fixtureUnixAddress  = append(unixBytes, unixBytes...)
	fixtureUnixV2       = append(lengthUnixBytes, fixtureUnixAddress...)
	fixtureTLV          = func() []byte {
		tlv := make([]byte, 2+rand.Intn(1<<12)) // Not enough to overflow, at least size two
		rand.Read(tlv)
		return tlv
	}()
	fixtureIPv4V2TLV = fixtureWithTLV(lengthV4Bytes, fixtureIPv4Address, fixtureTLV)
	fixtureIPv6V2TLV = fixtureWithTLV(lengthV6Bytes, fixtureIPv6Address, fixtureTLV)
	fixtureUnspecTLV = fixtureWithTLV(lengthUnspecBytes, []byte{}, fixtureTLV)

	// Arbitrary bytes following proxy bytes
	arbitraryTailBytes = []byte{'\x99', '\x97', '\x98'}
)

func pad(b []byte, n int) []byte {
	padding := make([]byte, n-len(b))
	return append(b, padding...)
}

var invalidParseV2Tests = []struct {
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
		desc:          "truncated v2 signature",
		reader:        newBufioReader(SIGV2[2:]),
		expectedError: ErrNoProxyProtocol,
	},
	{
		desc:          "v2 signature and nothing else",
		reader:        newBufioReader(SIGV2),
		expectedError: ErrCantReadProtocolVersionAndCommand,
	},
	{
		desc:          "v2 signature with invalid command",
		reader:        newBufioReader(append(SIGV2, invalidRune)),
		expectedError: ErrUnsupportedProtocolVersionAndCommand,
	},
	{
		desc:          "v2 signature with command but nothing else",
		reader:        newBufioReader(append(SIGV2, byte(PROXY))),
		expectedError: ErrCantReadAddressFamilyAndProtocol,
	},
	{
		desc:          "command proxy but inet family unspec",
		reader:        newBufioReader(append(SIGV2, byte(PROXY), byte(UNSPEC))),
		expectedError: ErrUnsupportedAddressFamilyAndProtocol,
	},
	{
		desc:          "v2 signature with command and invalid inet family", // translated to UNSPEC
		reader:        newBufioReader(append(SIGV2, byte(PROXY), invalidRune)),
		expectedError: ErrCantReadLength,
	},
	{
		desc:          "TCPv4 but no length",
		reader:        newBufioReader(append(SIGV2, byte(PROXY), byte(TCPv4))),
		expectedError: ErrCantReadLength,
	},
	{
		desc:          "TCPv4 but invalid length",
		reader:        newBufioReader(append(SIGV2, byte(PROXY), byte(TCPv4), invalidRune)),
		expectedError: ErrCantReadLength,
	},
	{
		desc:          "unspec but no length",
		reader:        newBufioReader(append(SIGV2, byte(LOCAL), byte(UNSPEC))),
		expectedError: ErrCantReadLength,
	},
	{
		desc:          "TCPv4 with mismatching length",
		reader:        newBufioReader(append(append(SIGV2, byte(PROXY), byte(TCPv4)), lengthV4Bytes...)),
		expectedError: ErrInvalidLength,
	},
	{
		desc:          "TCPv6 with mismatching length",
		reader:        newBufioReader(append(append(SIGV2, byte(PROXY), byte(TCPv6)), lengthV6Bytes...)),
		expectedError: ErrInvalidLength,
	},
	{
		desc:          "TCPv4 length zero but with address and ports",
		reader:        newBufioReader(append(append(append(SIGV2, byte(PROXY), byte(TCPv4)), lengthEmptyBytes...), fixtureIPv6Address...)),
		expectedError: ErrInvalidLength,
	},
	{
		desc:          "TCPv6 with IPv6 length but IPv4 address and ports",
		reader:        newBufioReader(append(append(append(SIGV2, byte(PROXY), byte(TCPv6)), lengthV6Bytes...), fixtureIPv4Address...)),
		expectedError: ErrInvalidLength,
	},
	{
		desc:          "unspec length greater than zero but no TLVs",
		reader:        newBufioReader(append(append(SIGV2, byte(LOCAL), byte(UNSPEC)), fixtureUnspecTLV[:2]...)),
		expectedError: ErrInvalidLength,
	},
}

func TestParseV2Invalid(t *testing.T) {
	for _, tt := range invalidParseV2Tests {
		t.Run(tt.desc, func(t *testing.T) {
			if _, err := Read(tt.reader); err != tt.expectedError {
				t.Fatalf("expected %s, actual %s", tt.expectedError, err.Error())
			}
		})
	}
}

var validParseAndWriteV2Tests = []struct {
	desc           string
	reader         *bufio.Reader
	expectedHeader *Header
}{
	{
		desc:   "local",
		reader: newBufioReader(append(append(SIGV2, byte(LOCAL), byte(TCPv4)), fixtureIPv4V2...)),
		expectedHeader: &Header{
			Version:           2,
			Command:           LOCAL,
			TransportProtocol: TCPv4,
			SourceAddr:        v4addr,
			DestinationAddr:   v4addr,
		},
	},
	{
		desc:   "local unspec",
		reader: newBufioReader(append(append(SIGV2, byte(LOCAL), byte(UNSPEC)), lengthUnspecBytes...)),
		expectedHeader: &Header{
			Version:           2,
			Command:           LOCAL,
			TransportProtocol: UNSPEC,
			SourceAddr:        nil,
			DestinationAddr:   nil,
		},
	},
	{
		desc:   "proxy TCPv4",
		reader: newBufioReader(append(append(SIGV2, byte(PROXY), byte(TCPv4)), fixtureIPv4V2...)),
		expectedHeader: &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: TCPv4,
			SourceAddr:        v4addr,
			DestinationAddr:   v4addr,
		},
	},
	{
		desc:   "proxy TCPv6",
		reader: newBufioReader(append(append(SIGV2, byte(PROXY), byte(TCPv6)), fixtureIPv6V2...)),
		expectedHeader: &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: TCPv6,
			SourceAddr:        v6addr,
			DestinationAddr:   v6addr,
		},
	},
	{
		desc:   "proxy TCPv4 with TLV",
		reader: newBufioReader(append(append(SIGV2, byte(PROXY), byte(TCPv4)), fixtureIPv4V2TLV...)),
		expectedHeader: &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: TCPv4,
			SourceAddr:        v4addr,
			DestinationAddr:   v4addr,
			rawTLVs:           fixtureTLV,
		},
	},
	{
		desc:   "proxy TCPv6 with TLV",
		reader: newBufioReader(append(append(SIGV2, byte(PROXY), byte(TCPv6)), fixtureIPv6V2TLV...)),
		expectedHeader: &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: TCPv6,
			SourceAddr:        v6addr,
			DestinationAddr:   v6addr,
			rawTLVs:           fixtureTLV,
		},
	},
	{
		desc:   "local unspec with TLV",
		reader: newBufioReader(append(append(SIGV2, byte(LOCAL), byte(UNSPEC)), fixtureUnspecTLV...)),
		expectedHeader: &Header{
			Version:           2,
			Command:           LOCAL,
			TransportProtocol: UNSPEC,
			SourceAddr:        nil,
			DestinationAddr:   nil,
			rawTLVs:           fixtureTLV,
		},
	},
	{
		desc:   "proxy UDPv4",
		reader: newBufioReader(append(append(SIGV2, byte(PROXY), byte(UDPv4)), fixtureIPv4V2...)),
		expectedHeader: &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: UDPv4,
			SourceAddr:        v4UDPAddr,
			DestinationAddr:   v4UDPAddr,
		},
	},
	{
		desc:   "proxy UDPv6",
		reader: newBufioReader(append(append(SIGV2, byte(PROXY), byte(UDPv6)), fixtureIPv6V2...)),
		expectedHeader: &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: UDPv6,
			SourceAddr:        v6UDPAddr,
			DestinationAddr:   v6UDPAddr,
		},
	},
	{
		desc:   "proxy unix stream",
		reader: newBufioReader(append(append(SIGV2, byte(PROXY), byte(UnixStream)), fixtureUnixV2...)),
		expectedHeader: &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: UnixStream,
			SourceAddr:        unixStreamAddr,
			DestinationAddr:   unixStreamAddr,
		},
	},
	{
		desc:   "proxy unix datagram",
		reader: newBufioReader(append(append(SIGV2, byte(PROXY), byte(UnixDatagram)), fixtureUnixV2...)),
		expectedHeader: &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: UnixDatagram,
			SourceAddr:        unixDatagramAddr,
			DestinationAddr:   unixDatagramAddr,
		},
	},
}

func TestParseV2Valid(t *testing.T) {
	for _, tt := range validParseAndWriteV2Tests {
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

func TestWriteV2Valid(t *testing.T) {
	for _, tt := range validParseAndWriteV2Tests {
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

var validParseV2PaddedTests = []struct {
	desc           string
	value          []byte
	expectedHeader *Header
}{
	{
		desc:  "proxy TCPv4",
		value: append(append(SIGV2, byte(PROXY), byte(TCPv4)), fixtureIPv4V2Padded...),
		expectedHeader: &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: TCPv4,
			SourceAddr:        v4addr,
			DestinationAddr:   v4addr,
			rawTLVs:           make([]byte, lengthPadded-lengthV4),
		},
	},
	{
		desc:  "proxy TCPv6",
		value: append(append(SIGV2, byte(PROXY), byte(TCPv6)), fixtureIPv6V2Padded...),
		expectedHeader: &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: TCPv6,
			SourceAddr:        v6addr,
			DestinationAddr:   v6addr,
			rawTLVs:           make([]byte, lengthPadded-lengthV6),
		},
	},
	{
		desc:  "proxy UDPv4",
		value: append(append(SIGV2, byte(PROXY), byte(UDPv4)), fixtureIPv4V2Padded...),
		expectedHeader: &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: UDPv4,
			SourceAddr:        v4addr,
			DestinationAddr:   v4addr,
			rawTLVs:           make([]byte, lengthPadded-lengthV4),
		},
	},
	{
		desc:  "proxy UDPv6",
		value: append(append(SIGV2, byte(PROXY), byte(UDPv6)), fixtureIPv6V2Padded...),
		expectedHeader: &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: UDPv6,
			SourceAddr:        v6addr,
			DestinationAddr:   v6addr,
			rawTLVs:           make([]byte, lengthPadded-lengthV6),
		},
	},
}

func TestParseV2Padded(t *testing.T) {
	for _, tt := range validParseV2PaddedTests {
		t.Run(tt.desc, func(t *testing.T) {
			reader := newBufioReader(append(tt.value, arbitraryTailBytes...))

			newHeader, err := Read(reader)
			if err != nil {
				t.Fatal("unexpected error ", err)
			}
			if !newHeader.EqualsTo(tt.expectedHeader) {
				t.Fatalf("expected %#v, actual %#v", tt.expectedHeader, newHeader)
			}

			// Check that remaining padding bytes have been flushed
			nextBytes, err := reader.Peek(len(arbitraryTailBytes))
			if err != nil {
				t.Fatal("unexpected error ", err)
			}
			if !reflect.DeepEqual(nextBytes, arbitraryTailBytes) {
				t.Fatalf("expected %#v, actual %#v", arbitraryTailBytes, nextBytes)
			}
		})
	}
}

func TestV2EqualsToTLV(t *testing.T) {
	eHdr := &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: TCPv4,
		SourceAddr:        v4addr,
		DestinationAddr:   v4addr,
	}
	hdr, err := Read(newBufioReader(append(append(SIGV2, byte(PROXY), byte(TCPv4)), fixtureIPv4V2TLV...)))
	if err != nil {
		t.Fatal("unexpected error ", err)
	}
	if eHdr.EqualsTo(hdr) {
		t.Fatalf("unexpectedly equal created: %#v, parsed: %#v", eHdr, hdr)
	}
	eHdr.rawTLVs = fixtureTLV[:]

	if !eHdr.EqualsTo(hdr) {
		t.Fatalf("unexpectedly unequal after tlv copy created: %#v, parsed: %#v", eHdr, hdr)
	}

	eHdr.rawTLVs[0] = eHdr.rawTLVs[0] + 1
	if eHdr.EqualsTo(hdr) {
		t.Fatalf("unexpectedly equal after changing tlv created: %#v, parsed: %#v", eHdr, hdr)
	}
}

var tlvFormatTests = []struct {
	desc   string
	header *Header
}{
	{
		desc: "proxy TCPv4",
		header: &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: TCPv4,
			SourceAddr:        v4addr,
			DestinationAddr:   v4addr,
			rawTLVs:           make([]byte, 1<<16),
		},
	},
	{
		desc: "proxy TCPv6",
		header: &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: TCPv6,
			SourceAddr:        v6addr,
			DestinationAddr:   v6addr,
			rawTLVs:           make([]byte, 1<<16),
		},
	},
	{
		desc: "proxy UDPv4",
		header: &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: UDPv4,
			SourceAddr:        v4addr,
			DestinationAddr:   v4addr,
			rawTLVs:           make([]byte, 1<<16),
		},
	},
	{
		desc: "proxy UDPv6",
		header: &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: UDPv6,
			SourceAddr:        v6addr,
			DestinationAddr:   v6addr,
			rawTLVs:           make([]byte, 1<<16),
		},
	},
	{
		desc: "local unspec",
		header: &Header{
			Version:           2,
			Command:           LOCAL,
			TransportProtocol: UNSPEC,
			SourceAddr:        nil,
			DestinationAddr:   nil,
			rawTLVs:           make([]byte, 1<<16),
		},
	},
}

func TestV2TLVFormatTooLargeTLV(t *testing.T) {
	for _, tt := range tlvFormatTests {
		t.Run(tt.desc, func(t *testing.T) {
			if _, err := tt.header.Format(); err != errUint16Overflow {
				t.Fatalf("missing or expected error when formatting too-large TLV %#v", err)
			}
		})

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
