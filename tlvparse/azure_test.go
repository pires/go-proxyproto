package tlvparse

import (
	"testing"

	"github.com/pires/go-proxyproto"
)

func TestFindAzurePrivateEndpointLinkID(t *testing.T) {
	tests := []struct {
		name       string
		tlvs       []proxyproto.TLV
		wantLinkID uint32
		wantFound  bool
	}{
		{
			name:       "nil TLVs",
			tlvs:       nil,
			wantLinkID: 0,
			wantFound:  false,
		},
		{
			name:       "empty TLVs",
			tlvs:       []proxyproto.TLV{},
			wantLinkID: 0,
			wantFound:  false,
		},
		{
			name: "AWS VPC endpoint ID",
			tlvs: []proxyproto.TLV{
				{
					Type:  0xEA,
					Value: []byte{0x01, 0x76, 0x70, 0x63, 0x65, 0x2d, 0x61, 0x62, 0x63, 0x31, 0x32, 0x33},
				},
			},
			wantLinkID: 0,
			wantFound:  false,
		},
		{
			name: "Azure but wrong subtype",
			tlvs: []proxyproto.TLV{
				{
					Type:  0xEE,
					Value: []byte{0x02, 0x01, 0x01, 0x01, 0x01},
				},
			},
			wantLinkID: 0,
			wantFound:  false,
		},
		{
			name: "Azure but wrong length",
			tlvs: []proxyproto.TLV{
				{
					Type:  0xEE,
					Value: []byte{0x02, 0x01, 0x01},
				},
			},
			wantLinkID: 0,
			wantFound:  false,
		},
		{
			name: "Azure link ID",
			tlvs: []proxyproto.TLV{
				{
					Type:  0xEE,
					Value: []byte{0x1, 0xc1, 0x45, 0x0, 0x21},
				},
			},
			wantLinkID: 0x210045c1,
			wantFound:  true,
		},
		{
			name: "Multiple TLVs",
			tlvs: []proxyproto.TLV{
				{ // AWS
					Type:  0xEA,
					Value: []byte{0x01, 0x76, 0x70, 0x63, 0x65, 0x2d, 0x61, 0x62, 0x63, 0x31, 0x32, 0x33},
				},
				{ // Azure but wrong subtype
					Type:  0xEE,
					Value: []byte{0x02, 0x01, 0x01, 0x01, 0x01},
				},
				{ // Azure but wrong length
					Type:  0xEE,
					Value: []byte{0x02, 0x01, 0x01},
				},
				{ // Correct
					Type:  0xEE,
					Value: []byte{0x1, 0xc1, 0x45, 0x0, 0x21},
				},
				{ // Also correct, but second in line
					Type:  0xEE,
					Value: []byte{0x1, 0xc1, 0x45, 0x0, 0x22},
				},
			},
			wantLinkID: 0x210045c1,
			wantFound:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLinkID, gotFound := FindAzurePrivateEndpointLinkID(tt.tlvs)
			if gotFound != tt.wantFound {
				t.Errorf("FindAzurePrivateEndpointLinkID() got1 = %v, want %v", gotFound, tt.wantFound)
			}
			if gotLinkID != tt.wantLinkID {
				t.Errorf("FindAzurePrivateEndpointLinkID() got = %v, want %v", gotLinkID, tt.wantLinkID)
			}
		})
	}
}
