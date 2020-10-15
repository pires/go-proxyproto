package tlvparse

import (
	"reflect"
	"testing"

	"github.com/pires/go-proxyproto"
)

var testCases = []struct {
	name  string
	raw   []byte
	types []proxyproto.PP2Type
	valid func(*testing.T, string, []proxyproto.TLV)
}{
	{
		name: "SSL haproxy cn",
		raw: []byte{
			0x0d, 0x0a, 0x0d, 0x0a,
			0x00, 0x0d, 0x0a, 0x51,
			0x55, 0x49, 0x54, 0x0a,
			0x21, 0x11, 0x00, 0x40,
			0x7f, 0x00, 0x00, 0x01,
			0x7f, 0x00, 0x00, 0x01,
			0xcc, 0x8a, 0x23, 0x2e,
			0x20, 0x00, 0x31, 0x07,
			0x00, 0x00, 0x00, 0x00,
			0x21, 0x00, 0x07, 0x54,
			0x4c, 0x53, 0x76, 0x31,
			0x2e, 0x33, 0x22, 0x00,
			0x1f, 0x45, 0x78, 0x61,
			0x6d, 0x70, 0x6c, 0x65,
			0x20, 0x43, 0x6f, 0x6d,
			0x6d, 0x6f, 0x6e, 0x20,
			0x4e, 0x61, 0x6d, 0x65,
			0x20, 0x43, 0x6c, 0x69,
			0x65, 0x6e, 0x74, 0x20,
			0x43, 0x65, 0x72, 0x74,
		},
		types: []proxyproto.PP2Type{proxyproto.PP2_TYPE_SSL},
		valid: func(t *testing.T, name string, tlvs []proxyproto.TLV) {
			if !IsSSL(tlvs[0]) {
				t.Fatalf("TestParseV2TLV %s: Expected tlvs[0] to be the SSL type", name)
			}

			ssl, err := SSL(tlvs[0])
			if err != nil {
				t.Fatalf("TestParseV2TLV %s: Unexpected error when parsing SSL %#v", name, err)
			}

			if !ssl.ClientSSL() {
				t.Fatalf("TestParseV2TLV %s: Expected ClientSSL() to be true", name)
			}

			if !ssl.ClientCertConn() {
				t.Fatalf("TestParseV2TLV %s: Expected ClientCertConn() to be true", name)
			}

			if !ssl.ClientCertSess() {
				t.Fatalf("TestParseV2TLV %s: Expected ClientCertSess() to be true", name)
			}

			ecn := "Example Common Name Client Cert"
			if acn, ok := ssl.ClientCN(); !ok {
				t.Fatalf("TestParseV2TLV %s: Expected ClientCN to exist", name)
			} else if acn != ecn {
				t.Fatalf("TestParseV2TLV %s: Unexpected ClientCN expected %#v, actual %#v", name, ecn, acn)
			}

			esslVer := "TLSv1.3"
			if asslVer, ok := ssl.SSLVersion(); !ok {
				t.Fatalf("TestParseV2TLV %s: Expected SSLVersion to exist", name)
			} else if asslVer != esslVer {
				t.Fatalf("TestParseV2TLV %s: Unexpected SSLVersion expected %#v, actual %#v", name, esslVer, asslVer)
			}

			if !ssl.Verified() {
				t.Fatalf("TestParseV2TLV %s: Expected Verified to be true", name)
			}
		},
	},
}

func TestParseV2TLV(t *testing.T) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tlvs := checkTLVs(t, tc.name, tc.raw, tc.types)
			tc.valid(t, tc.name, tlvs)
		})
	}
}

func TestPP2SSLMarshal(t *testing.T) {
	ver := "TLSv1.3"
	cn := "example.org"
	pp2 := PP2SSL{
		Client: PP2_BITFIELD_CLIENT_SSL,
		Verify: 0,
		TLV: []proxyproto.TLV{
			{
				Type:  proxyproto.PP2_SUBTYPE_SSL_VERSION,
				Value: []byte(ver),
			},
			{
				Type:  proxyproto.PP2_SUBTYPE_SSL_CN,
				Value: []byte(cn),
			},
		},
	}

	raw := []byte{0x1, 0x0, 0x0, 0x0, 0x0, 0x21, 0x0, 0x7, 0x54, 0x4c, 0x53, 0x76, 0x31, 0x2e, 0x33, 0x22, 0x0, 0xb, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x6f, 0x72, 0x67}
	want := proxyproto.TLV{
		Type:  proxyproto.PP2_TYPE_SSL,
		Value: raw,
	}

	tlv, err := pp2.Marshal()
	if err != nil {
		t.Fatalf("PP2SSL.Marshal() = %v", err)
	}

	if !reflect.DeepEqual(tlv, want) {
		t.Errorf("PP2SSL.Marshal() = %#v, want %#v", tlv, want)
	}
}
