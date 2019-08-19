// Type-Length-Value splitting and parsing for proxy protocol V2
// See spec https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt sections 2.2 to 2.7 and
// Amazon's extension https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-target-groups.html#proxy-protocol

package proxyproto

import (
	"encoding/binary"
	"errors"
	"regexp"
	"unicode"
	"unicode/utf8"
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

	// pp2_tlv_ssl.client  bit fields
	PP2_BITFIELD_CLIENT_SSL       uint8 = 0x01
	PP2_BITFIELD_CLIENT_CERT_CONN       = 0x02
	PP2_BITFIELD_CLIENT_CERT_SESS       = 0x04

	tlvSSLMinLen = 5 // len(pp2_tlv_ssl.client) + len(pp2_tlv_ssl.verify)
)

var (
	ErrTruncatedTLV    = errors.New("Truncated TLV")
	ErrMalformedTLV    = errors.New("Malformed TLV Value")
	ErrIncompatibleTLV = errors.New("Incompatible TLV type")

	vpceRe = regexp.MustCompile("[A-Za-z0-9-]*")
)

// PP2Type is the proxy protocol v2 type
type PP2Type byte

// TLV is a uninterpreted Type-Length-Value for V2 protocol, see section 2.2
type TLV struct {
	Type   PP2Type
	Length int
	Value  []byte
}

// splitTLVs splits the Type-Length-Value vector, returns the vector or an error.
func splitTLVs(raw []byte) ([]TLV, error) {
	var tlvs []TLV
	for i := 0; i < len(raw); {
		tlv := TLV{
			Type: PP2Type(raw[i]),
		}
		if len(raw)-i <= 3 {
			return nil, ErrTruncatedTLV
		}
		tlv.Length = int(binary.BigEndian.Uint16(raw[i+1 : i+3])) // Max length = 65K
		i += 3
		if i+tlv.Length > len(raw) {
			return nil, ErrTruncatedTLV
		}
		// Ignore no-op padding
		if tlv.Type != PP2_TYPE_NOOP {
			tlv.Value = make([]byte, tlv.Length)
			copy(tlv.Value, raw[i:i+tlv.Length])
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
	if !vpceRe.MatchString(string(t.Value)) {
		return "", ErrMalformedTLV
	}
	return string(t.Value[1:]), nil
}

// AWSVPCID returns the first AWS VPC ID in the TLV if it exists and is well-formed and a bool indicating one was found.
func AWSVPCID(tlvs []TLV) (string, bool) {
	for _, tlv := range tlvs {
		if vpc, err := tlv.AWSVPCID(); err == nil && vpc != "" {
			return vpc, true
		}
	}
	return "", false
}

// 2.2.5. The PP2_TYPE_SSL type and subtypes
/*
   struct pp2_tlv_ssl {
           uint8_t  client;
           uint32_t verify;
           struct pp2_tlv sub_tlv[0];
   };
*/
type PP2SSL struct {
	Client uint8 // The <client> field is made of a bit field from the following values,
	// indicating which element is present: PP2_BITFIELD_CLIENT_SSL,
	// PP2_BITFIELD_CLIENT_CERT_CONN, PP2_BITFIELD_CLIENT_CERT_SESS
	Verify uint32 // Verify will be zero if the client presented a certificate
	// and it was successfully verified, and non-zero otherwise.
	TLV []TLV
}

// Verified is true if the client presented a certificate and it was successfully verified
func (s PP2SSL) Verified() bool {
	return s.Verify == 0
}

// ClientSSL indicates that the client connected over SSL/TLS.  When true, SSLVersion will return the version.
func (s PP2SSL) ClientSSL() bool {
	return s.Client&PP2_BITFIELD_CLIENT_SSL == PP2_BITFIELD_CLIENT_SSL
}

// ClientCertConn indicates that the client provided a certificate over the current connection.
func (s PP2SSL) ClientCertConn() bool {
	return s.Client&PP2_BITFIELD_CLIENT_CERT_CONN == PP2_BITFIELD_CLIENT_CERT_CONN
}

// ClientCertSess indicates that the client provided a certificate at least once over the TLS session this
// connection belongs to.
func (s PP2SSL) ClientCertSess() bool {
	return s.Client&PP2_BITFIELD_CLIENT_CERT_SESS == PP2_BITFIELD_CLIENT_CERT_SESS
}

// SSLVersion returns the US-ASCII string representation of the TLS version and whether that extension exists.
func (s PP2SSL) SSLVersion() (string, bool) {
	for _, tlv := range s.TLV {
		if tlv.Type == PP2_SUBTYPE_SSL_VERSION {
			return string(tlv.Value), true
		}
	}
	return "", false
}

// ClientCN returns the string representation (in UTF8) of the Common Name field (OID: 2.5.4.3) of the client
// certificate's Distinguished Name and whether that extension exists.
func (s PP2SSL) ClientCN() (string, bool) {
	for _, tlv := range s.TLV {
		if tlv.Type == PP2_SUBTYPE_SSL_CN {
			return string(tlv.Value), true
		}
	}
	return "", false
}

// SSLType is true if the TLV is type SSL
func (t TLV) SSLType() bool {
	return t.Type.SSL() && t.Length >= tlvSSLMinLen
}

// SSL returns the pp2_tlv_ssl from section 2.2.5 or errors with ErrIncompatibleTLV or ErrMalformedTLV
func (t TLV) SSL() (PP2SSL, error) {
	ssl := PP2SSL{}
	if !t.SSLType() {
		return ssl, ErrIncompatibleTLV
	}
	if t.Length < tlvSSLMinLen {
		return ssl, ErrMalformedTLV
	}
	ssl.Client = t.Value[0]
	ssl.Verify = binary.BigEndian.Uint32(t.Value[1:5])
	var err error
	ssl.TLV, err = splitTLVs(t.Value[5:])
	if err != nil {
		return PP2SSL{}, err
	}
	versionFound := !ssl.ClientSSL()
	var cnFound bool
	for _, tlv := range ssl.TLV {
		switch tlv.Type {
		case PP2_SUBTYPE_SSL_VERSION:
			/*
				The PP2_CLIENT_SSL flag indicates that the client connected over SSL/TLS. When
				this field is present, the US-ASCII string representation of the TLS version is
				appended at the end of the field in the TLV format using the type
				PP2_SUBTYPE_SSL_VERSION.
			*/
			if tlv.Length == 0 || !isASCII(tlv.Value) {
				return PP2SSL{}, ErrMalformedTLV
			}
			versionFound = true
		case PP2_SUBTYPE_SSL_CN:
			/*
				In all cases, the string representation (in UTF8) of the Common Name field
				(OID: 2.5.4.3) of the client certificate's Distinguished Name, is appended
				using the TLV format and the type PP2_SUBTYPE_SSL_CN. E.g. "example.com".
			*/
			if tlv.Length == 0 || !utf8.Valid(tlv.Value) {
				return PP2SSL{}, ErrMalformedTLV
			}
			cnFound = true
		}
	}
	if !(versionFound && cnFound) {
		return PP2SSL{}, ErrMalformedTLV
	}
	return ssl, nil
}

// SSL returns the first PP2SSL if it exists and is well formed as well as bool indicating if it was found.
func SSL(tlvs []TLV) (PP2SSL, bool) {
	for _, t := range tlvs {
		if ssl, err := t.SSL(); err == nil {
			return ssl, true
		}
	}
	return PP2SSL{}, false
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

// SSL is true if the type is SSL
func (p PP2Type) SSL() bool {
	return p == PP2_TYPE_SSL
}

// isASCII checks whether a byte slice has all characters that fit in the ascii character set, including the null byte.
func isASCII(b []byte) bool {
	for _, c := range b {
		if c > unicode.MaxASCII {
			return false
		}
	}
	return true
}
