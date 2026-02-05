package proxyproto

import (
	"bufio"
	"bytes"
	iorand "crypto/rand"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

var (
	invalidRune = byte('\x99')

	// Lengths to use in tests.
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

	// If life gives you lemons, make mojitos.
	portBytes = func() []byte {
		a := make([]byte, 2)
		binary.BigEndian.PutUint16(a, testValidPort)
		return a
	}()

	unixBytes = pad([]byte("socket"), 108)

	// Tests don't care if source and destination addresses and ports are the same.
	addressesIPv4 = append(v4ip.To4(), v4ip.To4()...)
	addressesIPv6 = append(v6ip.To16(), v6ip.To16()...)
	ports         = append(portBytes, portBytes...)

	// Fixtures to use in tests.
	fixtureIPv4Address  = append(addressesIPv4, ports...)
	fixtureIPv4V2       = append(lengthV4Bytes, fixtureIPv4Address...)
	fixtureIPv4V2Padded = append(append(lengthPaddedBytes, fixtureIPv4Address...), make([]byte, lengthPadded-lengthV4)...)
	fixtureIPv6Address  = append(addressesIPv6, ports...)
	fixtureIPv6V2       = append(lengthV6Bytes, fixtureIPv6Address...)
	fixtureIPv6V2Padded = append(append(lengthPaddedBytes, fixtureIPv6Address...), make([]byte, lengthPadded-lengthV6)...)
	fixtureUnixAddress  = append(unixBytes, unixBytes...)
	fixtureUnixV2       = append(lengthUnixBytes, fixtureUnixAddress...)
	fixtureTLV          = func() []byte {
		tlv := make([]byte, 100)
		_, _ = iorand.Read(tlv)
		return tlv
	}()
	fixtureIPv4V2TLV = fixtureWithTLV(lengthV4Bytes, fixtureIPv4Address, fixtureTLV)
	fixtureIPv6V2TLV = fixtureWithTLV(lengthV6Bytes, fixtureIPv6Address, fixtureTLV)
	fixtureUnspecTLV = fixtureWithTLV(lengthUnspecBytes, []byte{}, fixtureTLV)

	fixtureMediumTLV   = make([]byte, 2048)
	fixtureV2MediumTLV = fixtureWithTLV(lengthV4Bytes, fixtureIPv4Address, fixtureMediumTLV)

	fixtureTooLargeTLV   = make([]byte, 10*1024)
	fixtureV2TooLargeTLV = fixtureWithTLV(lengthV4Bytes, fixtureIPv4Address, fixtureTooLargeTLV)

	// Arbitrary bytes following proxy bytes.
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
		reader:        newBufioReader([]byte(testNoProtocol)),
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
		expectedError: ErrInvalidAddress,
	},
	{
		desc:          "TCPv6 with mismatching length",
		reader:        newBufioReader(append(append(SIGV2, byte(PROXY), byte(TCPv6)), lengthV6Bytes...)),
		expectedError: ErrInvalidAddress,
	},
	{
		desc:          "TCPv4 length zero but with address and ports",
		reader:        newBufioReader(append(append(append(SIGV2, byte(PROXY), byte(TCPv4)), lengthEmptyBytes...), fixtureIPv6Address...)),
		expectedError: ErrInvalidLength,
	},
	{
		desc:          "TCPv6 with IPv6 length but IPv4 address and ports",
		reader:        newBufioReader(append(append(append(SIGV2, byte(PROXY), byte(TCPv6)), lengthV6Bytes...), fixtureIPv4Address...)),
		expectedError: ErrInvalidAddress,
	},
	{
		desc:          "unspec length greater than zero but no TLVs",
		reader:        newBufioReader(append(append(SIGV2, byte(LOCAL), byte(UNSPEC)), fixtureUnspecTLV[:2]...)),
		expectedError: ErrInvalidLength,
	},
	{
		desc:          "TCPv4 with too large TLV",
		reader:        newBufioReader(append(append(SIGV2, byte(PROXY), byte(TCPv4)), fixtureV2TooLargeTLV...)),
		expectedError: ErrInvalidLength,
	},
}

func TestParseV2Invalid(t *testing.T) {
	for _, tt := range invalidParseV2Tests {
		t.Run(tt.desc, func(t *testing.T) {
			if _, err := Read(tt.reader); err != tt.expectedError {
				t.Fatalf("expected %v, actual %v", tt.expectedError, err)
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
	{
		desc:   "proxy TCPv4 with medium TLV",
		reader: newBufioReader(append(append(SIGV2, byte(PROXY), byte(TCPv4)), fixtureV2MediumTLV...)),
		expectedHeader: &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: TCPv4,
			SourceAddr:        v4addr,
			DestinationAddr:   v4addr,
			rawTLVs:           fixtureMediumTLV,
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
			if err := w.Flush(); err != nil {
				t.Fatal("unexpected error ", err)
			}

			// Read written bytes to validate written header
			r := bufio.NewReaderSize(&b, readBufferSize)
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
	return bufio.NewReaderSize(bytes.NewReader(b), readBufferSize)
}

func fixtureWithTLV(cur []byte, addr []byte, tlv []byte) []byte {
	tlen, err := addTLVLen(cur, len(tlv))
	if err != nil {
		panic(err)
	}

	return append(append(tlen, addr...), tlv...)
}

func Test_parseUnixName(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		b    []byte
		want string
	}{
		{
			name: "simple name, no null terminator",
			b:    []byte("socketname"),
			want: "socketname",
		},
		{
			name: "simple name with single null byte",
			b:    append([]byte("socketname"), 0),
			want: "socketname",
		},
		{
			name: "long name with null terminator in the middle",
			b:    append([]byte("sock\000etname"), 0),
			want: "sock",
		},
		{
			name: "empty input",
			b:    []byte{},
			want: "",
		},
		{
			name: "all null bytes",
			b:    []byte{0, 0, 0},
			want: "",
		},
		{
			name: "mixed bytes with null at end",
			b:    append([]byte("abc123"), 0),
			want: "abc123",
		},
		{
			name: "name with null in middle",
			b:    []byte{'t', 'e', 0, 's', 't'},
			want: "te",
		},
		{
			name: "no null, binary data",
			b:    []byte{0x7f, 0xfe, 0x3c},
			want: string([]byte{0x7f, 0xfe, 0x3c}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseUnixName(tt.b)
			if got != tt.want {
				t.Errorf("parseUnixName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_formatUnixName(t *testing.T) {
	maxLen := int(lengthUnix) / 2
	longName := strings.Repeat("a", maxLen+5)
	shortName := "socket"

	longFormatted := formatUnixName(longName)
	if len(longFormatted) != maxLen {
		t.Fatalf("formatUnixName() length = %d, want %d", len(longFormatted), maxLen)
	}
	if got := parseUnixName(longFormatted); got != longName[:maxLen] {
		t.Errorf("formatUnixName() long parse = %q, want %q", got, longName[:maxLen])
	}

	shortFormatted := formatUnixName(shortName)
	if len(shortFormatted) != maxLen {
		t.Fatalf("formatUnixName() length = %d, want %d", len(shortFormatted), maxLen)
	}
	if got := parseUnixName(shortFormatted); got != shortName {
		t.Errorf("formatUnixName() short parse = %q, want %q", got, shortName)
	}
	if !bytes.HasPrefix(shortFormatted, []byte(shortName)) {
		t.Errorf("formatUnixName() short prefix = %q, want prefix %q", shortFormatted, shortName)
	}
}
