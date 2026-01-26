// Package tlvparse provides helpers for PROXY protocol TLVs.
//
// Amazon's application extension to TLVs for NLB VPC endpoint services
// https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-target-groups.html#proxy-protocol
package tlvparse

import (
	"regexp"

	"github.com/pires/go-proxyproto"
)

//nolint:revive // Names follow the spec.
const (
	// PP2_TYPE_AWS identifies AWS TLV extensions.
	PP2_TYPE_AWS            = 0xEA
	// PP2_SUBTYPE_AWS_VPCE_ID identifies the VPC endpoint ID subtype.
	PP2_SUBTYPE_AWS_VPCE_ID = 0x01
)

var vpceRe = regexp.MustCompile("^[A-Za-z0-9-]*$")

// IsAWSVPCEndpointID reports whether tlv contains an AWS VPC endpoint ID.
func IsAWSVPCEndpointID(tlv proxyproto.TLV) bool {
	return tlv.Type == PP2_TYPE_AWS && len(tlv.Value) > 0 && tlv.Value[0] == PP2_SUBTYPE_AWS_VPCE_ID
}

// AWSVPCEndpointID returns the AWS VPC endpoint ID if present.
func AWSVPCEndpointID(tlv proxyproto.TLV) (string, error) {
	if !IsAWSVPCEndpointID(tlv) {
		return "", proxyproto.ErrIncompatibleTLV
	}
	vpce := string(tlv.Value[1:])
	if !vpceRe.MatchString(vpce) {
		return "", proxyproto.ErrMalformedTLV
	}
	return vpce, nil
}

// FindAWSVPCEndpointID returns the first AWS VPC ID in the TLV if it exists and is well-formed.
func FindAWSVPCEndpointID(tlvs []proxyproto.TLV) string {
	for _, tlv := range tlvs {
		if vpc, err := AWSVPCEndpointID(tlv); err == nil && vpc != "" {
			return vpc
		}
	}
	return ""
}
