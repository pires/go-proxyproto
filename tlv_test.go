package proxyproto

import (
	"bufio"
	"bytes"
	"testing"
)

var (
	fixtureOneByteTLV    = []byte{byte(PP2_TYPE_MIN_CUSTOM) + 1}
	fixtureTwoByteTLV    = []byte{byte(PP2_TYPE_MIN_CUSTOM) + 2, 0x00}
	fixtureEmptyLenTLV   = []byte{byte(PP2_TYPE_MIN_CUSTOM) + 3, 0x00, 0x01}
	fixturePartialLenTLV = []byte{byte(PP2_TYPE_MIN_CUSTOM) + 3, 0x00, 0x02, 0x00}
)

var invalidTLVTests = []struct {
	name          string
	reader        *bufio.Reader
	expectedError error
}{
	{
		name: "One byte TLV",
		reader: newBufioReader(append(append(SIGV2, byte(PROXY), byte(TCPv4)), fixtureWithTLV(lengthV4Bytes, fixtureIPv4Address,
			fixtureOneByteTLV)...)),
		expectedError: ErrTruncatedTLV,
	},
	{
		name: "Two byte TLV",
		reader: newBufioReader(append(append(SIGV2, byte(PROXY), byte(TCPv4)), fixtureWithTLV(lengthV4Bytes, fixtureIPv4Address,
			fixtureTwoByteTLV)...)),
		expectedError: ErrTruncatedTLV,
	},
	{
		name: "Empty Len TLV",
		reader: newBufioReader(append(append(SIGV2, byte(PROXY), byte(TCPv4)), fixtureWithTLV(lengthV4Bytes, fixtureIPv4Address,
			fixtureEmptyLenTLV)...)),
		expectedError: ErrTruncatedTLV,
	},
	{
		name: "Partial Len TLV",
		reader: newBufioReader(append(append(SIGV2, byte(PROXY), byte(TCPv4)), fixtureWithTLV(lengthV4Bytes, fixtureIPv4Address,
			fixturePartialLenTLV)...)),
		expectedError: ErrTruncatedTLV,
	},
}

func TestValid0Length(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader(append(append(SIGV2, byte(PROXY), byte(TCPv4)), fixtureWithTLV(lengthV4Bytes, fixtureIPv4Address, []byte{byte(PP2_TYPE_MIN_CUSTOM), 0x00, 0x00})...)))
	h, err := Read(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tlvs, err := h.TLVs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tlvs) != 1 {
		t.Fatalf("expected 1 tlv, got %d", len(tlvs))
	}
	if len(tlvs[0].Value) != 0 {
		t.Fatalf("expected 0 byte tlv value, got %x", tlvs[0].Value)
	}
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
	pp2RegTypes := []PP2Type{
		PP2_TYPE_ALPN, PP2_TYPE_AUTHORITY, PP2_TYPE_CRC32C, PP2_TYPE_NOOP, PP2_TYPE_UNIQUE_ID,
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

func TestJoinTLVs(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		tlvs []TLV
	}{
		{
			name: "authority TLV",
			raw:  append([]byte{byte(PP2_TYPE_AUTHORITY), 0x00, 0x0B}, []byte("example.org")...),
			tlvs: []TLV{{
				Type:  PP2_TYPE_AUTHORITY,
				Value: []byte("example.org"),
			}},
		},
		{
			name: "empty TLV",
			raw:  []byte{byte(PP2_TYPE_NOOP), 0x00, 0x00},
			tlvs: []TLV{{
				Type:  PP2_TYPE_NOOP,
				Value: nil,
			}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if raw, err := JoinTLVs(tc.tlvs); err != nil {
				t.Fatalf("unexpected error: %v", err)
			} else if !bytes.Equal(raw, tc.raw) {
				t.Errorf("expected %#v, got %#v", tc.raw, raw)
			}
		})
	}
}
