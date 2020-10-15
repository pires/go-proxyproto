// Azure's application extension to TLVs for Private Link Services
// https://docs.microsoft.com/en-us/azure/private-link/private-link-service-overview#getting-connection-information-using-tcp-proxy-v2

package tlvparse

import (
	"encoding/binary"

	"github.com/pires/go-proxyproto"
)

const (
	// Azure's extension
	PP2_TYPE_AZURE                           = 0xEE
	PP2_SUBTYPE_AZURE_PRIVATEENDPOINT_LINKID = 0x01
)

// IsAzurePrivateEndpointLinkID returns true if given TLV matches Azure Private Endpoint LinkID format
func isAzurePrivateEndpointLinkID(tlv proxyproto.TLV) bool {
	return tlv.Type == PP2_TYPE_AZURE && len(tlv.Value) == 5 && tlv.Value[0] == PP2_SUBTYPE_AZURE_PRIVATEENDPOINT_LINKID
}

// AzurePrivateEndpointLinkID returns linkID if given TLV matches Azure Private Endpoint LinkID format
//
// Format description:
//	Field	Length (Octets)	Description
//	Type	1	PP2_TYPE_AZURE (0xEE)
//	Length	2	Length of value
//	Value	1	PP2_SUBTYPE_AZURE_PRIVATEENDPOINT_LINKID (0x01)
//			4	UINT32 (4 bytes) representing the LINKID of the private endpoint. Encoded in little endian format.
func azurePrivateEndpointLinkID(tlv proxyproto.TLV) (uint32, error) {
	if !isAzurePrivateEndpointLinkID(tlv) {
		return 0, proxyproto.ErrIncompatibleTLV
	}
	linkID := binary.LittleEndian.Uint32(tlv.Value[1:])
	return linkID, nil
}

// FindAzurePrivateEndpointLinkID returns the first Azure Private Endpoint LinkID if it exists in the TLV collection
// and a boolean indicating if it was found.
func FindAzurePrivateEndpointLinkID(tlvs []proxyproto.TLV) (uint32, bool) {
	for _, tlv := range tlvs {
		if linkID, err := azurePrivateEndpointLinkID(tlv); err == nil {
			return linkID, true
		}
	}
	return 0, false
}
