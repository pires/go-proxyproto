package tlvparse

import (
	"encoding/binary"
	"testing"

	"github.com/pires/go-proxyproto"
)

var awsTestCases = []struct {
	name  string
	raw   []byte
	types []proxyproto.PP2Type
	valid func(*testing.T, string, []proxyproto.TLV)
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
		types: []proxyproto.PP2Type{proxyproto.PP2_TYPE_CRC32C, PP2_TYPE_AWS, proxyproto.PP2_TYPE_NOOP},
		valid: func(t *testing.T, name string, tlvs []proxyproto.TLV) {
			if !IsAWSVPCEndpointID(tlvs[1]) {
				t.Fatalf("TestParseV2TLV %s: Expected tlvs[1] to be an AWSVPCEndpointID type", name)
			}

			vpce := "vpce-08d2bf15fac5001c9"
			if vpca, err := AWSVPCEndpointID(tlvs[1]); err != nil {
				t.Fatalf("TestParseV2TLV %s: Unexpected error when parsing AWSVPCEndpointID", name)
			} else if vpca != vpce {
				t.Fatalf("TestParseV2TLV %s: Unexpected VPC ID from tlvs[1] expected %#v, actual %#v", name, vpce, vpca)
			}

			if vpca := FindAWSVPCEndpointID(tlvs); vpca == "" {
				t.Fatalf("TestParseV2TLV %s: Expected to find AWSVPCEndpointID %#v in TLVs", name, vpce)
			} else if vpca != vpce {
				t.Fatalf("TestParseV2TLV %s: Unexpected AWSVPCEndpointID from header expected %#v, actual %#v", name, vpce, vpca)
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
		types: []proxyproto.PP2Type{proxyproto.PP2_TYPE_CRC32C, PP2_TYPE_AWS, proxyproto.PP2_TYPE_NOOP},
		valid: func(t *testing.T, name string, tlvs []proxyproto.TLV) {
			if !IsAWSVPCEndpointID(tlvs[1]) {
				t.Fatalf("TestParseV2TLV %s: Expected tlvs[1] to be an AWS VPC endpoint ID type", name)
			}

			vpce := "vpce-00eafc458ec97b833"
			if vpca, err := AWSVPCEndpointID(tlvs[1]); err != nil {
				t.Fatalf("TestParseV2TLV %s: Unexpected error when parsing AWS VPC ID", name)
			} else if vpca != vpce {
				t.Fatalf("TestParseV2TLV %s: Unexpected VPC ID from tlvs[1] expected %#v, actual %#v", name, vpce, vpca)
			}

			if vpca := FindAWSVPCEndpointID(tlvs); vpca == "" {
				t.Fatalf("TestParseV2TLV %s: Expected to find VPC ID %#v in TLVs", name, vpce)
			} else if vpca != vpce {
				t.Fatalf("TestParseV2TLV %s: Unexpected VPC ID from header expected %#v, actual %#v", name, vpce, vpca)
			}

		},
	},
}

func TestV2TLVAWSVPCEBadChars(t *testing.T) {
	badVPCE := "vcpe-!?***&&&&&&&"
	rawTLVs := vpceTLV(badVPCE)
	tlvs, err := proxyproto.SplitTLVs(rawTLVs)
	if len(tlvs) != 1 {
		t.Fatalf("TestV2TLVAWSVPCEBadChars: unexpected TLV length expected: %#v, actual: %#v", 1, tlvs)
	}
	if err != nil {
		t.Fatalf("TestV2TLVAWSVPCEBadChars: unexpected TLV parsing error %#v", err)
	}

	_, err = AWSVPCEndpointID(tlvs[0])
	if err != proxyproto.ErrMalformedTLV {
		t.Fatalf("TestV2TLVAWSVPCEBadChars: unexpected error actual: %#v", err)
	}

	if FindAWSVPCEndpointID(tlvs) != "" {
		t.Fatal("TestV2TLVAWSVPCEBadChars: AWSVPCEndpointID unexpectedly found")
	}

	rawTLVs = vpceTLV("")
	tlvs, err = proxyproto.SplitTLVs(rawTLVs)
	if len(tlvs) != 1 {
		t.Fatalf("TestV2TLVAWSVPCEBadChars: unexpected TLV length expected: %#v, actual: %#v", 1, tlvs)
	}
	if err != nil {
		t.Fatalf("TestV2TLVAWSVPCEBadChars: unexpected TLV parsing error %#v", err)
	}

	parsedVPCE, err := AWSVPCEndpointID(tlvs[0])
	if err != nil {
		t.Fatalf("TestV2TLVAWSVPCEBadChars: unexpected error actual: %#v", err)
	}

	if parsedVPCE != "" {
		t.Fatalf("TestV2TLVAWSVPCEBadChars: found non-empty vpce, actual: %#v", parsedVPCE)
	}

	parsedVPCE = FindAWSVPCEndpointID(tlvs)
	if parsedVPCE != "" {
		t.Fatal("TestV2TLVAWSVPCEBadChars: AWSVPECID unexpectedly found")
	}
}

func TestParseAWSVPCEndpointIDTLVs(t *testing.T) {
	for _, tc := range awsTestCases {
		t.Run(tc.name, func(t *testing.T) {
			tlvs := checkTLVs(t, tc.name, tc.raw, tc.types)
			tc.valid(t, tc.name, tlvs)
		})
	}
}

func TestV2TLVAWSUnknownSubtype(t *testing.T) {
	vpce := "vpce-abc1234"

	rawTLVs := vpceTLV(vpce)
	tlvs, err := proxyproto.SplitTLVs(rawTLVs)
	if len(tlvs) != 1 {
		t.Fatalf("TestV2TLVAWSUnknownSubtype: unexpected TLV length expected: %#v, actual: %#v", 1, tlvs)
	}
	if err != nil {
		t.Fatalf("TestV2TLVAWSUnknownSubtype: unexpected TLV parsing error %#v", err)
	}

	avpce, err := AWSVPCEndpointID(tlvs[0])
	if err != nil {
		t.Fatalf("TestV2TLVAWSUnknownSubtype: unexpected AWSVPCEndpointID error actual: %#v", err)
	}
	if avpce != vpce {
		t.Fatalf("TestV2TLVAWSUnknownSubtype: unexpected vpce value expected: %#v, actual: %#v", vpce, avpce)
	}
	avpce = FindAWSVPCEndpointID(tlvs)
	if avpce == "" {
		t.Fatal("TestV2TLVAWSUnknownSubtype: AWSVPCEndpointID unexpectedly missing")
	}
	if avpce != vpce {
		t.Fatalf("TestV2TLVAWSUnknownSubtype: unexpected AWSVPCEndpointID value expected: %#v, actual: %#v", vpce, avpce)
	}

	subtypeIndex := 3
	// Sanity check
	if rawTLVs[subtypeIndex] != PP2_SUBTYPE_AWS_VPCE_ID {
		t.Fatalf("TestV2TLVAWSUnknownSubtype: unexpected subtype expected %x, actual %x", PP2_SUBTYPE_AWS_VPCE_ID, rawTLVs[subtypeIndex])
	}

	rawTLVs[subtypeIndex] = PP2_SUBTYPE_AWS_VPCE_ID + 1

	tlvs, err = proxyproto.SplitTLVs(rawTLVs)
	if len(tlvs) != 1 {
		t.Fatalf("TestV2TLVAWSUnknownSubtype: unexpected TLV length expected: %#v, actual: %#v", 1, tlvs)
	}
	if err != nil {
		t.Fatalf("TestV2TLVAWSUnknownSubtype: unexpected TLV parsing error %#v", err)
	}

	if IsAWSVPCEndpointID(tlvs[0]) {
		t.Fatalf("TestV2TLVAWSUnknownSubtype: AWSVPCEType() unexpectedly true after changing subtype")
	}

	_, err = AWSVPCEndpointID(tlvs[0])
	if err != proxyproto.ErrIncompatibleTLV {
		t.Fatalf("TestV2TLVAWSUnknownSubtype: unexpected AWSVPCEndpointID error expected %#v, actual: %#v", proxyproto.ErrIncompatibleTLV, err)
	}

	if FindAWSVPCEndpointID(tlvs) != "" {
		t.Fatal("TestV2TLVAWSUnknownSubtype: AWSVPCEndpointID unexpectedly exists despite invalid subtype")
	}
}

func vpceTLV(vpce string) []byte {
	tlv := []byte{
		PP2_TYPE_AWS, 0x00, 0x00, PP2_SUBTYPE_AWS_VPCE_ID,
	}
	binary.BigEndian.PutUint16(tlv[1:3], uint16(len(vpce)+1)) // +1 for subtype
	return append(tlv, []byte(vpce)...)
}
