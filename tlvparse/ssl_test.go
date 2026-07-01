package tlvparse

import (
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/pires/go-proxyproto"
)

// tlsVersion13 is the TLS version 1.3 string.
const tlsVersion13 string = "TLSv1.3"

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

			esslVer := tlsVersion13
			if asslVer, ok := ssl.SSLVersion(); !ok {
				t.Fatalf("TestParseV2TLV %s: Expected SSLVersion to exist", name)
			} else if asslVer != esslVer {
				t.Fatalf("TestParseV2TLV %s: Unexpected SSLVersion expected %#v, actual %#v", name, esslVer, asslVer)
			}

			if _, ok := ssl.SSLCipher(); ok {
				t.Fatalf("TestParseV2TLV %s: Unexpected SSLCipher", name)
			}

			if !ssl.Verified() {
				t.Fatalf("TestParseV2TLV %s: Expected Verified to be true", name)
			}
		},
	},
	{
		name: "SSL haproxy cipher",
		raw: []byte{
			0x0d, 0x0a, 0x0d, 0x0a,
			0x00, 0x0d, 0x0a, 0x51,
			0x55, 0x49, 0x54, 0x0a,
			0x21, 0x21, 0x00, 0x4f,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0xff, 0xff,
			0x0a, 0x01, 0x5b, 0x0e,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0xff, 0xff,
			0x0a, 0x01, 0x01, 0x9f,
			0xf4, 0x7c, 0x01, 0xbb,
			0x20, 0x00, 0x28, 0x01,
			0x00, 0x00, 0x00, 0x00,
			0x21, 0x00, 0x07, 0x54,
			0x4c, 0x53, 0x76, 0x31,
			0x2e, 0x33, 0x23, 0x00,
			0x16, 0x54, 0x4c, 0x53,
			0x5f, 0x41, 0x45, 0x53,
			0x5f, 0x32, 0x35, 0x36,
			0x5f, 0x47, 0x43, 0x4d,
			0x5f, 0x53, 0x48, 0x41,
			0x33, 0x38, 0x34,
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

			if ssl.ClientCertConn() {
				t.Fatalf("TestParseV2TLV %s: Expected ClientCertConn() to be false", name)
			}

			if ssl.ClientCertSess() {
				t.Fatalf("TestParseV2TLV %s: Expected ClientCertSess() to be false", name)
			}

			if _, ok := ssl.ClientCN(); ok {
				t.Fatalf("TestParseV2TLV %s: Expected ClientCN to not exist", name)
			}

			esslVer := "TLSv1.3"
			if asslVer, ok := ssl.SSLVersion(); !ok {
				t.Fatalf("TestParseV2TLV %s: Expected SSLVersion to exist", name)
			} else if asslVer != esslVer {
				t.Fatalf("TestParseV2TLV %s: Unexpected SSLVersion expected %#v, actual %#v", name, esslVer, asslVer)
			}

			esslCipher := "TLS_AES_256_GCM_SHA384"
			if asslCipher, ok := ssl.SSLCipher(); !ok {
				t.Fatalf("TestParseV2TLV %s: Expected SSLCipher to exist", name)
			} else if asslCipher != esslCipher {
				t.Fatalf("TestParseV2TLV %s: Unexpected SSLCipher expected %#v, actual %#v", name, esslCipher, asslCipher)
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

func TestPP2SSLClientCertAndFindSSL(t *testing.T) {
	// Exercise the public convenience helpers that are not touched by the
	// HAProxy fixture tests: finding the first well-formed SSL TLV and returning
	// the raw client certificate subtype without copying or decoding it.
	cert := []byte{0x30, 0x03, 0x01}
	tlv := mustMarshalSSL(t, PP2SSL{
		Client: PP2_BITFIELD_CLIENT_SSL,
		Verify: 0,
		TLV: []proxyproto.TLV{
			{Type: proxyproto.PP2_SUBTYPE_SSL_VERSION, Value: []byte(tlsVersion13)},
			{Type: proxyproto.PP2_SUBTYPE_SSL_CLIENT_CERT, Value: cert},
		},
	})

	ssl, ok := FindSSL([]proxyproto.TLV{
		{Type: proxyproto.PP2_TYPE_ALPN, Value: []byte("h2")},
		tlv,
	})
	if !ok {
		t.Fatal("expected to find SSL TLV")
	}

	gotCert, ok := ssl.ClientCert()
	if !ok {
		t.Fatal("expected client certificate TLV")
	}
	if !reflect.DeepEqual(gotCert, cert) {
		t.Fatalf("unexpected certificate bytes: got %#v want %#v", gotCert, cert)
	}

	if _, ok := FindSSL([]proxyproto.TLV{{Type: proxyproto.PP2_TYPE_ALPN, Value: []byte("h2")}}); ok {
		t.Fatal("unexpectedly found SSL TLV")
	}

	noTLS := mustMarshalSSL(t, PP2SSL{Client: 0, Verify: 1})
	parsed, err := SSL(noTLS)
	if err != nil {
		t.Fatalf("unexpected non-TLS SSL TLV parse error: %v", err)
	}
	if _, ok := parsed.SSLVersion(); ok {
		t.Fatal("unexpected SSL version when client SSL bit is not set")
	}
	if _, ok := parsed.ClientCert(); ok {
		t.Fatal("unexpected client certificate when subtype is absent")
	}
}

func TestSSLRejectsMalformedTLVs(t *testing.T) {
	// Keep malformed SSL sub-TLV validation explicit. These cases protect the
	// parser's stricter rules: TLS clients must include a non-empty ASCII version,
	// CN must be valid UTF-8, and cipher/version fields must be ASCII.
	validVersion := proxyproto.TLV{
		Type:  proxyproto.PP2_SUBTYPE_SSL_VERSION,
		Value: []byte(tlsVersion13),
	}

	tests := []struct {
		name string
		tlv  proxyproto.TLV
		want error
	}{
		{
			name: "incompatible type",
			tlv:  proxyproto.TLV{Type: proxyproto.PP2_TYPE_ALPN, Value: make([]byte, tlvSSLMinLen)},
			want: proxyproto.ErrIncompatibleTLV,
		},
		{
			name: "short SSL value",
			tlv:  proxyproto.TLV{Type: proxyproto.PP2_TYPE_SSL, Value: make([]byte, tlvSSLMinLen-1)},
			want: proxyproto.ErrIncompatibleTLV,
		},
		{
			name: "truncated sub TLV",
			tlv:  sslTLV(PP2_BITFIELD_CLIENT_SSL, []byte{byte(proxyproto.PP2_SUBTYPE_SSL_VERSION), 0, 2, 'T'}),
			want: proxyproto.ErrTruncatedTLV,
		},
		{
			name: "missing required version",
			tlv:  sslTLV(PP2_BITFIELD_CLIENT_SSL, nil),
			want: proxyproto.ErrMalformedTLV,
		},
		{
			name: "empty version",
			tlv:  sslTLV(PP2_BITFIELD_CLIENT_SSL, mustJoinTLVs(t, proxyproto.TLV{Type: proxyproto.PP2_SUBTYPE_SSL_VERSION})),
			want: proxyproto.ErrMalformedTLV,
		},
		{
			name: "non ASCII version",
			tlv: sslTLV(PP2_BITFIELD_CLIENT_SSL, mustJoinTLVs(t, proxyproto.TLV{
				Type:  proxyproto.PP2_SUBTYPE_SSL_VERSION,
				Value: []byte{0xff},
			})),
			want: proxyproto.ErrMalformedTLV,
		},
		{
			name: "empty common name",
			tlv: sslTLV(PP2_BITFIELD_CLIENT_SSL, mustJoinTLVs(t,
				validVersion,
				proxyproto.TLV{Type: proxyproto.PP2_SUBTYPE_SSL_CN},
			)),
			want: proxyproto.ErrMalformedTLV,
		},
		{
			name: "invalid UTF-8 common name",
			tlv: sslTLV(PP2_BITFIELD_CLIENT_SSL, mustJoinTLVs(t,
				validVersion,
				proxyproto.TLV{Type: proxyproto.PP2_SUBTYPE_SSL_CN, Value: []byte{0xff}},
			)),
			want: proxyproto.ErrMalformedTLV,
		},
		{
			name: "empty cipher",
			tlv: sslTLV(PP2_BITFIELD_CLIENT_SSL, mustJoinTLVs(t,
				validVersion,
				proxyproto.TLV{Type: proxyproto.PP2_SUBTYPE_SSL_CIPHER},
			)),
			want: proxyproto.ErrMalformedTLV,
		},
		{
			name: "non ASCII cipher",
			tlv: sslTLV(PP2_BITFIELD_CLIENT_SSL, mustJoinTLVs(t,
				validVersion,
				proxyproto.TLV{Type: proxyproto.PP2_SUBTYPE_SSL_CIPHER, Value: []byte{0xff}},
			)),
			want: proxyproto.ErrMalformedTLV,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SSL(tt.tlv)
			if !errors.Is(err, tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, err)
			}
		})
	}
}

func TestPP2SSLMarshalPropagatesSubTLVError(t *testing.T) {
	// Marshal delegates sub-TLV encoding to proxyproto.JoinTLVs; oversized
	// sub-TLVs must surface that error instead of emitting an invalid SSL TLV.
	_, err := PP2SSL{
		TLV: []proxyproto.TLV{{
			Type:  proxyproto.PP2_SUBTYPE_SSL_VERSION,
			Value: make([]byte, math.MaxUint16+1),
		}},
	}.Marshal()
	if err == nil {
		t.Fatal("expected oversized sub-TLV error")
	}
}

func mustMarshalSSL(t *testing.T, ssl PP2SSL) proxyproto.TLV {
	t.Helper()

	tlv, err := ssl.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal SSL TLV: %v", err)
	}
	return tlv
}

func sslTLV(client uint8, rawSubTLVs []byte) proxyproto.TLV {
	// Build the outer PP2_TYPE_SSL value directly so tests can inject malformed
	// raw sub-TLV bytes that proxyproto.JoinTLVs would normally refuse to create.
	value := make([]byte, tlvSSLMinLen)
	value[0] = client
	binary.BigEndian.PutUint32(value[1:5], 0)
	value = append(value, rawSubTLVs...)
	return proxyproto.TLV{Type: proxyproto.PP2_TYPE_SSL, Value: value}
}

func mustJoinTLVs(t *testing.T, tlvs ...proxyproto.TLV) []byte {
	t.Helper()

	raw, err := proxyproto.JoinTLVs(tlvs)
	if err != nil {
		t.Fatalf("failed to join TLVs: %v", err)
	}
	return raw
}
