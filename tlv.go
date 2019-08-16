// Type-Length-Value splitting and parsing for proxy protocol V2
// See spec https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt sections 2.2 to 2.7 and
// Amazon's extension https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-target-groups.html#proxy-protocol

package proxyproto

import (
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
)

const (
	// Section 2.2
	PP2_TYPE_ALPN           PP2Type = 0x01
	PP2_TYPE_AUTHORITY              = 0x02
	PP2_TYPE_CRC32C                 = 0x03
	PP2_TYPE_NOOP                   = 0x04
	PP2_TYPE_SSL                    = 0x20
	PP2_SUBTYPE_SSL_VERSION         = 0x21
	PP2_SUBTYPE_SSL_CN              = 0x22
	PP2_SUBTYPE_SSL_CIPHER          = 0x23
	PP2_SUBTYPE_SSL_SIG_ALG         = 0x24
	PP2_SUBTYPE_SSL_KEY_ALG         = 0x25
	PP2_TYPE_NETNS                  = 0x30
	// Section 2.2.7, reserved types
	PP2_TYPE_MIN_CUSTOM     = 0xE0
	PP2_TYPE_MAX_CUSTOM     = 0xEF
	PP2_TYPE_MIN_EXPERIMENT = 0xF0
	PP2_TYPE_MAX_EXPERIMENT = 0xF7
	PP2_TYPE_MIN_FUTURE     = 0xF8
	PP2_TYPE_MAX_FUTURE     = 0xFF
	// Amazon's extension
	PP2_TYPE_AWS            = 0xEA
	PP2_SUBTYPE_AWS_VPCE_ID = 0x01
)

var (
	ErrTruncatedTLV    = errors.New("Truncated TLV")
	ErrMalformedTLV    = errors.New("Malformed TLV Value")
	ErrIncompatibleTLV = errors.New("Incompatible TLV type")
)

// PP2Type is the proxy protocol v2 type
type PP2Type byte

// TLV is a uninterpreted Type-Length-Value for V2 protocol, see section 2.2
type TLV struct {
	Type   PP2Type
	Length int
	Value  []byte
}

// readTLVs reads the Type-Length-Value vector, returns the vector or an error.  Reads until EOF or an error occurs.
func readTLVs(reader io.Reader) ([]TLV, error) {
	rest, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	var tlvs []TLV
	for i := 0; i < len(rest); {
		tlv := TLV{
			Type: PP2Type(rest[i]),
		}
		tlv.Length = int(binary.BigEndian.Uint16(rest[i+1 : i+3])) // Max length = 65K
		i += 3
		if i+tlv.Length > len(rest) {
			return nil, ErrTruncatedTLV
		}
		// Ignore no-op padding
		if tlv.Type != PP2_TYPE_NOOP {
			tlv.Value = make([]byte, tlv.Length)
			copy(tlv.Value, rest[i:i+tlv.Length])
		}
		i += tlv.Length
		tlvs = append(tlvs, tlv)
	}
	return tlvs, nil
}

// AWSVPCType is true if the TLV is an AWS extension with VPC subtype
func (t TLV) AWSVPCType() bool {
	return t.Type.AWS() && t.Length >= 1 && t.Value[0] == PP2_SUBTYPE_AWS_VPCE_ID
}

// AWSVPCID returns the vpc-id of an AWS VPC extension TLV or errors with ErrIncompatibleTLV or ErrMalformedTLV if
// it's the wrong TLV type or has a malformed VPC ID (containing chars other than 0-9, a-z, -)
func (t TLV) AWSVPCID() (string, error) {
	if !t.AWSVPCType() {
		return "", ErrIncompatibleTLV
	}
	for _, c := range t.Value[1:] {
		if !(c == byte('-') || (c >= byte('0') && c <= byte('9')) || (c >= byte('a') && c <= byte('z'))) {
			return "", ErrMalformedTLV
		}
	}
	return string(t.Value[1:]), nil
}

// AWSVPCID returns the first AWS VPC ID in the TLV if it exists and is well-formed.  Returns an empty string otherwise.
func (header *Header) AWSVPCID() string {
	for _, tlv := range header.TLVs {
		if vpc, err := tlv.AWSVPCID(); err == nil && vpc != "" {
			return vpc
		}
	}
	return ""
}

// Registered is true if the type is registered in the spec, see section 2.2
func (p PP2Type) Registered() bool {
	switch p {
	case PP2_TYPE_ALPN,
		PP2_TYPE_AUTHORITY,
		PP2_TYPE_CRC32C,
		PP2_TYPE_NOOP,
		PP2_TYPE_SSL,
		PP2_SUBTYPE_SSL_VERSION,
		PP2_SUBTYPE_SSL_CN,
		PP2_SUBTYPE_SSL_CIPHER,
		PP2_SUBTYPE_SSL_SIG_ALG,
		PP2_SUBTYPE_SSL_KEY_ALG,
		PP2_TYPE_NETNS:
		return true
	}
	return false
}

// App is true if the type is reserved for application specific data, see section 2.2.7
func (p PP2Type) App() bool {
	return p >= PP2_TYPE_MIN_CUSTOM && p <= PP2_TYPE_MAX_CUSTOM
}

// Experiment is true if the type is reserved for temporary experimental use by application developers, see section 2.2.7
func (p PP2Type) Experiment() bool {
	return p >= PP2_TYPE_MIN_EXPERIMENT && p <= PP2_TYPE_MAX_EXPERIMENT
}

// Future is true is the type is reserved for future use, see section 2.2.7
func (p PP2Type) Future() bool {
	return p >= PP2_TYPE_MIN_FUTURE
}

// Spec is true if the type is covered by the spec, see section 2.2 and 2.2.7
func (p PP2Type) Spec() bool {
	return p.Registered() || p.App() || p.Experiment() || p.Future()
}

// AWS is true if the type is the AWS extension
func (p PP2Type) AWS() bool {
	return p == PP2_TYPE_AWS
}
