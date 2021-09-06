package tlvparse

import (
	"testing"

	"github.com/pires/go-proxyproto"
)

func TestExtractPSCConnectionID(t *testing.T) {
	tests := []struct {
		name                string
		tlvs                []proxyproto.TLV
		wantPSCConnectionID uint64
		wantFound           bool
	}{
		{
			name:      "nil TLVs",
			tlvs:      nil,
			wantFound: false,
		},
		{
			name:      "empty TLVs",
			tlvs:      []proxyproto.TLV{},
			wantFound: false,
		},
		{
			name: "AWS VPC endpoint ID",
			tlvs: []proxyproto.TLV{
				{
					Type:  0xEA,
					Value: []byte{0x01, 0x76, 0x70, 0x63, 0x65, 0x2d, 0x61, 0x62, 0x63, 0x31, 0x32, 0x33},
				},
			},
			wantFound: false,
		},
		{
			name: "GCP link ID",
			tlvs: []proxyproto.TLV{
				{
					Type:  PP2_TYPE_GCP,
					Value: []byte{'\xff', '\xff', '\xff', '\xff', '\xc0', '\xa8', '\x64', '\x02'},
				},
			},
			wantPSCConnectionID: 18446744072646845442,
			wantFound:           true,
		},
		{
			name: "Multiple TLVs",
			tlvs: []proxyproto.TLV{
				{ // AWS
					Type:  0xEA,
					Value: []byte{0x01, 0x76, 0x70, 0x63, 0x65, 0x2d, 0x61, 0x62, 0x63, 0x31, 0x32, 0x33},
				},
				{ // Azure
					Type:  0xEE,
					Value: []byte{0x02, 0x01, 0x01, 0x01, 0x01},
				},
				{ // GCP but wrong length
					Type:  0xE0,
					Value: []byte{0xff, 0xff, 0xff},
				},
				{ // Correct
					Type:  0xE0,
					Value: []byte{'\xff', '\xff', '\xff', '\xff', '\xc0', '\xa8', '\x64', '\x02'},
				},
			},
			wantPSCConnectionID: 18446744072646845442,
			wantFound:           true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			linkID, hasLinkID := ExtractPSCConnectionID(tt.tlvs)
			if hasLinkID != tt.wantFound {
				t.Errorf("ExtractPSCConnectionID() got1 = %v, want %v", hasLinkID, tt.wantFound)
			}
			if linkID != tt.wantPSCConnectionID {
				t.Errorf("ExtractPSCConnectionID() got = %v, want %v", linkID, tt.wantPSCConnectionID)
			}
		})
	}
}
