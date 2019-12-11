package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"
)

var (
	fixtureOneByteTLV    = []byte{PP2_TYPE_MIN_CUSTOM + 1}
	fixtureTwoByteTLV    = []byte{PP2_TYPE_MIN_CUSTOM + 2, 0x00}
	fixtureEmptyLenTLV   = []byte{PP2_TYPE_MIN_CUSTOM + 3, 0x00, 0x01}
	fixturePartialLenTLV = []byte{PP2_TYPE_MIN_CUSTOM + 3, 0x00, 0x02, 0x00}
)

func checkTLVs(t *testing.T, name string, raw []byte, expected []PP2Type) []TLV {
	header, err := parseVersion2(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("%s: Unexpected error reading header %#v", name, err)
	}

	tlvs, err := header.TLVs()
	if err != nil {
		t.Fatalf("%s: Unexpected error splitting TLVS %#v", name, err)
	}

	if len(tlvs) != len(expected) {
		t.Fatalf("%s: Expected %d TLVs, actual %d", name, len(expected), len(tlvs))
	}

	for i, et := range expected {
		if at := tlvs[i].Type; at != et {
			t.Fatalf("%s: Expected type %X, actual %X", name, et, at)
		}
	}

	return tlvs
}

func formatTLV(tlv TLV) []byte {
	out := make([]byte, 3) // 1 = type + 2 = uint16 length
	out[0] = byte(tlv.Type)
	binary.BigEndian.PutUint16(out[1:3], uint16(tlv.Length))
	return append(out, tlv.Value...)
}

var invalidTLVTests = []struct {
	name          string
	reader        *bufio.Reader
	expectedError error
}{
	{
		name: "One byte TLV",
		reader: newBufioReader(append(append(SIGV2, PROXY, TCPv4), fixtureWithTLV(lengthV4Bytes, fixtureIPv4Address,
			fixtureOneByteTLV)...)),
		expectedError: ErrTruncatedTLV,
	},
	{
		name: "Two byte TLV",
		reader: newBufioReader(append(append(SIGV2, PROXY, TCPv4), fixtureWithTLV(lengthV4Bytes, fixtureIPv4Address,
			fixtureTwoByteTLV)...)),
		expectedError: ErrTruncatedTLV,
	},
	{
		name: "Empty Len TLV",
		reader: newBufioReader(append(append(SIGV2, PROXY, TCPv4), fixtureWithTLV(lengthV4Bytes, fixtureIPv4Address,
			fixtureEmptyLenTLV)...)),
		expectedError: ErrTruncatedTLV,
	},
	{
		name: "Partial Len TLV",
		reader: newBufioReader(append(append(SIGV2, PROXY, TCPv4), fixtureWithTLV(lengthV4Bytes, fixtureIPv4Address,
			fixturePartialLenTLV)...)),
		expectedError: ErrTruncatedTLV,
	},
}

func TestInvalidV2TLV(t *testing.T) {
	for _, tc := range invalidTLVTests {
		t.Run(tc.name, func(t *testing.T) {
			if hdr, err := Read(tc.reader); err != nil {
				t.Fatalf("TestInvalidV2TLV %s: unexpected error reading proxy protocol %#v", tc.name, err)
			} else if _, err := hdr.TLVs(); err != tc.expectedError {
				t.Fatalf("TestInvalidV2TLV %s: expected %#v, actual %#v", tc.name, tc.expectedError, err)
			}
		})
	}
}

func TestV2TLVPP2Registered(t *testing.T) {
	pp2RegTypes := []PP2Type {
		PP2_TYPE_ALPN, PP2_TYPE_AUTHORITY, PP2_TYPE_CRC32C, PP2_TYPE_NOOP,
		PP2_TYPE_SSL, PP2_SUBTYPE_SSL_VERSION, PP2_SUBTYPE_SSL_CN,
		PP2_SUBTYPE_SSL_CIPHER, PP2_SUBTYPE_SSL_SIG_ALG, PP2_SUBTYPE_SSL_KEY_ALG,
		PP2_TYPE_NETNS,
	}
	pp2RegMap := make(map[PP2Type]bool)
	for _, p := range pp2RegTypes {
		pp2RegMap[p] = true
		if !p.Registered() {
			t.Fatalf("TestV2TLVPP2Registered: type %x should be registered", p)
		}
		if !p.Spec() {
			t.Fatalf("TestV2TLVPP2Registered: type %x should be in spec", p)
		}
		if p.App() {
			t.Fatalf("TestV2TLVPP2Registered: type %x unexpectedly app", p)
		}
		if p.Experiment() {
			t.Fatalf("TestV2TLVPP2Registered: type %x unexpectedly experiment", p)
		}
		if p.Future() {
			t.Fatalf("TestV2TLVPP2Registered: type %x unexpectedly future", p)
		}
	}

	lastType := PP2Type(0xFF)
	for i := PP2Type(0x00); i < lastType; i++ {
		if !pp2RegMap[i] {
			if i.Registered() {
				t.Fatalf("TestV2TLVPP2Registered: type %x unexpectedly registered", i)
			}
		}
	}

	if lastType.Registered() {
		t.Fatalf("TestV2TLVPP2Registered: type %x unexpectedly registered", lastType)
	}
}
