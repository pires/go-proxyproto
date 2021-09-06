package tlvparse

import (
	"encoding/binary"

	"github.com/pires/go-proxyproto"
)

const (
	// PP2_TYPE_GCP indicates a Google Cloud Platform header
	PP2_TYPE_GCP proxyproto.PP2Type = 0xE0
)

// ExtractPSCConnectionID returns the first PSC Connection ID in the TLV if it exists and is well-formed and
// a bool indicating one was found.
func ExtractPSCConnectionID(tlvs []proxyproto.TLV) (uint64, bool) {
	for _, tlv := range tlvs {
		if linkID, err := pscConnectionID(tlv); err == nil {
			return linkID, true
		}
	}
	return 0, false
}

// pscConnectionID returns the ID of a GCP PSC extension TLV or errors with ErrIncompatibleTLV or
// ErrMalformedTLV if it's the wrong TLV type or is malformed.
//
//	Field	Length (bytes)	Description
//	Type	1	PP2_TYPE_GCP (0xE0)
//	Length	2	Length of value (always 0x0008)
//	Value	8	The 8-byte PSC Connection ID (decode to uint64; big endian)
//
// For example proxyproto.TLV{Type:0xea, Length:8, Value:[]byte{0xff, 0xff, 0xff, 0xff, 0xc0, 0xa8, 0x64, 0x02}}
// will be decoded as 18446744072646845442.
//
// See https://cloud.google.com/vpc/docs/configure-private-service-connect-producer
func pscConnectionID(t proxyproto.TLV) (uint64, error) {
	if !isPSCConnectionID(t) {
		return 0, proxyproto.ErrIncompatibleTLV
	}
	linkID := binary.BigEndian.Uint64(t.Value)
	return linkID, nil
}

func isPSCConnectionID(t proxyproto.TLV) bool {
	return t.Type == PP2_TYPE_GCP && len(t.Value) == 8
}
