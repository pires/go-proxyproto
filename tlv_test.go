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

var testCases = []struct {
	name  string
	raw   []byte
	types []PP2Type
	valid func(*testing.T, string, []TLV)
}{
	{
		name: "VPCE example",
		// https://github.com/aws/elastic-load-balancing-tools/blob/c8eee30ab991ab4c57dc37d1c58f09f67bd534aa/proprot/tst/com/amazonaws/proprot/Compatibility_AwsNetworkLoadBalancerTest.java#L41..L67
		raw: []byte{
			0x0d, 0x0a, 0x0d, 0x0a, /* Start of Sig */
			0x00, 0x0d, 0x0a, 0x51,
			0x55, 0x49, 0x54, 0x0a, /* End of Sig */
			0x21, 0x11, 0x00, 0x54, /* ver_cmd, fam and len */
			0xac, 0x1f, 0x07, 0x71, /* Caller src ip */
			0xac, 0x1f, 0x0a, 0x1f, /* Endpoint dst ip */
			0xc8, 0xf2, 0x00, 0x50, /* Proxy src port & dst port */
			0x03, 0x00, 0x04, 0xe8, /* CRC TLV start */
			0xd6, 0x89, 0x2d, 0xea, /* CRC TLV cont, VPCE id TLV start */
			0x00, 0x17, 0x01, 0x76,
			0x70, 0x63, 0x65, 0x2d,
			0x30, 0x38, 0x64, 0x32,
			0x62, 0x66, 0x31, 0x35,
			0x66, 0x61, 0x63, 0x35,
			0x30, 0x30, 0x31, 0x63,
			0x39, 0x04, 0x00, 0x24, /* VPCE id TLV end, NOOP TLV start*/
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, /* NOOP TLV end */
		},
		types: []PP2Type{PP2_TYPE_CRC32C, PP2_TYPE_AWS, PP2_TYPE_NOOP},
		valid: func(t *testing.T, name string, tlvs []TLV) {
			if !tlvs[1].AWSVPCEType() {
				t.Fatalf("TestParseV2TLV %s: Expected tlvs[1] to be an AWS VPC type", name)
			}

			vpce := "vpce-08d2bf15fac5001c9"
			if vpca, err := tlvs[1].AWSVPCEID(); err != nil {
				t.Fatalf("TestParseV2TLV %s: Unexpected error when parsing AWS VPC ID", name)
			} else if vpca != vpce {
				t.Fatalf("TestParseV2TLV %s: Unexpected VPC ID from tlvs[1] expected %#v, actual %#v", name, vpce, vpca)
			}

			if vpca, ok := AWSVPECID(tlvs); !ok {
				t.Fatalf("TestParseV2TLV %s: Expected to find VPC ID %#v in TLVs", name, vpce)
			} else if vpca != vpce {
				t.Fatalf("TestParseV2TLV %s: Unexpected VPC ID from header expected %#v, actual %#v", name, vpce, vpca)
			}

		},
	},
	{
		name: "VPCE capture",
		raw: []byte{
			0x0d, 0x0a, 0x0d, 0x0a,
			0x00, 0x0d, 0x0a, 0x51,
			0x55, 0x49, 0x54, 0x0a,
			0x21, 0x11, 0x00, 0x54,
			0xc0, 0xa8, 0x2c, 0x0a,
			0xc0, 0xa8, 0x2c, 0x07,
			0xcc, 0x3e, 0x24, 0x1b,
			0x03, 0x00, 0x04, 0xb9,
			0x28, 0x6f, 0xa6, 0xea,
			0x00, 0x17, 0x01, 0x76,
			0x70, 0x63, 0x65, 0x2d,
			0x30, 0x30, 0x65, 0x61,
			0x66, 0x63, 0x34, 0x35,
			0x38, 0x65, 0x63, 0x39,
			0x37, 0x62, 0x38, 0x33,
			0x33, 0x04, 0x00, 0x24,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		},
		types: []PP2Type{PP2_TYPE_CRC32C, PP2_TYPE_AWS, PP2_TYPE_NOOP},
		valid: func(t *testing.T, name string, tlvs []TLV) {
			if !tlvs[1].AWSVPCEType() {
				t.Fatalf("TestParseV2TLV %s: Expected tlvs[1] to be an AWS VPC type", name)
			}

			vpce := "vpce-00eafc458ec97b833"
			if vpca, err := tlvs[1].AWSVPCEID(); err != nil {
				t.Fatalf("TestParseV2TLV %s: Unexpected error when parsing AWS VPC ID", name)
			} else if vpca != vpce {
				t.Fatalf("TestParseV2TLV %s: Unexpected VPC ID from tlvs[1] expected %#v, actual %#v", name, vpce, vpca)
			}

			if vpca, ok := AWSVPECID(tlvs); !ok {
				t.Fatalf("TestParseV2TLV %s: Expected to find VPC ID %#v in TLVs", name, vpce)
			} else if vpca != vpce {
				t.Fatalf("TestParseV2TLV %s: Unexpected VPC ID from header expected %#v, actual %#v", name, vpce, vpca)
			}

		},
	},
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
		types: []PP2Type{PP2_TYPE_SSL},
		valid: func(t *testing.T, name string, tlvs []TLV) {
			if !tlvs[0].SSLType() {
				t.Fatalf("TestParseV2TLV %s: Expected tlvs[0] to be the SSL type", name)
			}

			ssl, err := tlvs[0].SSL()
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

func vpceTLV(vpce string) []byte {
	tlv := []byte{
		PP2_TYPE_AWS, 0x00, 0x00, PP2_SUBTYPE_AWS_VPCE_ID,
	}
	binary.BigEndian.PutUint16(tlv[1:3], uint16(len(vpce) + 1)) // +1 for subtype
	return append(tlv, []byte(vpce)...)
}


func TestV2TLVAWSVPCEBadChars(t *testing.T) {
	badVPCE := "vcpe-!?***&&&&&&&"
	hdr := &Header{
		Version:            2,
		Command:            PROXY,
		TransportProtocol:  TCPv4,
		SourceAddress:      v4addr,
		DestinationAddress: v4addr,
		SourcePort:         PORT,
		DestinationPort:    PORT,
		rawTLVs:            vpceTLV(badVPCE),
	}
	tlvs, err := hdr.TLVs()
	if len(tlvs) != 1 {
		t.Fatalf("TestV2TLVAWSVPCEBadChars: unexpected TLV length expected: %#v, actual: %#v", 1, tlvs)
	}
	if err != nil {
		t.Fatalf("TestV2TLVAWSVPCEBadChars: unexpected TLV parsing error %#v", err)
	}

	_, err = tlvs[0].AWSVPCEID()
	if err != ErrMalformedTLV {
		t.Fatalf("TestV2TLVAWSVPCEBadChars: unexpected error actual: %#v", err)
	}
	_, ok := AWSVPECID(tlvs)
	if ok {
		t.Fatal("TestV2TLVAWSVPCEBadChars: AWSVPECID unexpectedly found")
	}

	hdr.rawTLVs = vpceTLV("")
	tlvs, err = hdr.TLVs()
	if len(tlvs) != 1 {
		t.Fatalf("TestV2TLVAWSVPCEBadChars: unexpected TLV length expected: %#v, actual: %#v", 1, tlvs)
	}
	if err != nil {
		t.Fatalf("TestV2TLVAWSVPCEBadChars: unexpected TLV parsing error %#v", err)
	}

	parsedVPCE, err := tlvs[0].AWSVPCEID()
	if err != nil {
		t.Fatalf("TestV2TLVAWSVPCEBadChars: unexpected error actual: %#v", err)
	}

	if parsedVPCE != "" {
		t.Fatalf("TestV2TLVAWSVPCEBadChars: found non-empty vpce, actual: %#v", parsedVPCE)
	}

	_, ok = AWSVPECID(tlvs)
	if ok {
		t.Fatal("TestV2TLVAWSVPCEBadChars: AWSVPECID unexpectedly found")
	}
}

func TestV2TLVAWSUnknownSubtype(t *testing.T) {
	vpce := "vpce-abc1234"
	hdr := &Header{
		Version:            2,
		Command:            PROXY,
		TransportProtocol:  TCPv4,
		SourceAddress:      v4addr,
		DestinationAddress: v4addr,
		SourcePort:         PORT,
		DestinationPort:    PORT,
		rawTLVs:            vpceTLV(vpce),
	}

	tlvs, err := hdr.TLVs()
	if len(tlvs) != 1 {
		t.Fatalf("TestV2TLVAWSUnknownSubtype: unexpected TLV length expected: %#v, actual: %#v", 1, tlvs)
	}
	if err != nil {
		t.Fatalf("TestV2TLVAWSUnknownSubtype: unexpected TLV parsing error %#v", err)
	}

	avpce, err := tlvs[0].AWSVPCEID()
	if err != nil {
		t.Fatalf("TestV2TLVAWSUnknownSubtype: unexpected AWSVPCEID error actual: %#v", err)
	}
	if avpce != vpce {
		t.Fatalf("TestV2TLVAWSUnknownSubtype: unexpected vpce value expected: %#v, actual: %#v", vpce, avpce)
	}
	avpce, ok := AWSVPECID(tlvs)
	if !ok {
		t.Fatal("TestV2TLVAWSUnknownSubtype: AWSVPECID unexpectedly missing")
	}
	if avpce != vpce {
		t.Fatalf("TestV2TLVAWSUnknownSubtype: unexpected vpce value expected: %#v, actual: %#v", vpce, avpce)
	}

	subtypeIndex := 3
	// Sanity check
	if hdr.rawTLVs[subtypeIndex] != PP2_SUBTYPE_AWS_VPCE_ID {
		t.Fatalf("TestV2TLVAWSUnknownSubtype: unexpected subtype expected %x, actual %x", PP2_SUBTYPE_AWS_VPCE_ID, hdr.rawTLVs[subtypeIndex])
	}

	hdr.rawTLVs[subtypeIndex] = PP2_SUBTYPE_AWS_VPCE_ID + 1

	tlvs, err = hdr.TLVs()
	if len(tlvs) != 1 {
		t.Fatalf("TestV2TLVAWSUnknownSubtype: unexpected TLV length expected: %#v, actual: %#v", 1, tlvs)
	}
	if err != nil {
		t.Fatalf("TestV2TLVAWSUnknownSubtype: unexpected TLV parsing error %#v", err)
	}

	if tlvs[0].AWSVPCEType() {
		t.Fatalf("TestV2TLVAWSUnknownSubtype: AWSVPCEType() unexpectedly true after changing subtype")
	}

	_, err = tlvs[0].AWSVPCEID()
	if err != ErrIncompatibleTLV {
		t.Fatalf("TestV2TLVAWSUnknownSubtype: unexpected AWSVPCEID error expected %#v, actual: %#v", ErrIncompatibleTLV, err)
	}

	_, ok = AWSVPECID(tlvs)
	if ok {
		t.Fatal("TestV2TLVAWSUnknownSubtype: AWSVPECID unexpectedly exists despite invalid subtype")
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