package proxyproto

import (
	"bufio"
	"bytes"
	"testing"
)

func TestParseV2TLV(t *testing.T) {
	// https://github.com/aws/elastic-load-balancing-tools/blob/c8eee30ab991ab4c57dc37d1c58f09f67bd534aa/proprot/tst/com/amazonaws/proprot/Compatibility_AwsNetworkLoadBalancerTest.java#L41..L67
	raw := []byte{
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
	}
	header, err := parseVersion2(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatal("TestParseV2TLV: Unexpected error ", err)
	}
	if len(header.TLVs) != 3 {
		t.Fatalf("TestParseV2TLV: Expected 3 TLVs, actual %d", len(header.TLVs))
	}
	for i, et := range []PP2Type{PP2_TYPE_CRC32C, PP2_TYPE_AWS, PP2_TYPE_NOOP} {
		if at := header.TLVs[i].Type; at != et {
			t.Fatalf("TestParseV2TLV: Expected type %X, avtual %X", et, at)
		}
	}

	if !header.TLVs[1].AWSVPCType() {
		t.Fatalf("TestParseV2TLV: Expected TLVs[1] to be an AWS VPC type")
	}

	vpce := "vpce-08d2bf15fac5001c9"
	if vpca, err := header.TLVs[1].AWSVPCID(); err != nil {
		t.Fatalf("TestParseV2TLV: Unexpected error when parsing AWS VPC ID")
	} else if vpca != vpce {
		t.Fatalf("TestParseV2TLV: Unexpected VPC ID from TLV[1] expected %#v, actual %#v", vpce, vpca)
	}

	if vpca := header.AWSVPCID(); vpca != vpce {
		t.Fatalf("TestParseV2TLV: Unexpected VPC ID from header expected %#v, actual %#v", vpce, vpca)
	}
}
