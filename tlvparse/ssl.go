package tlvparse

import (
	"encoding/binary"
	"unicode"
	"unicode/utf8"

	"github.com/pires/go-proxyproto"
)

// pp2_tlv_ssl.client bit fields.
//
//nolint:revive // Names follow the PROXY protocol spec.
const (
	// PP2_BITFIELD_CLIENT_SSL indicates the client used SSL/TLS.
	PP2_BITFIELD_CLIENT_SSL uint8 = 0x01
	// PP2_BITFIELD_CLIENT_CERT_CONN indicates cert on the connection.
	PP2_BITFIELD_CLIENT_CERT_CONN uint8 = 0x02
	// PP2_BITFIELD_CLIENT_CERT_SESS indicates cert in the session.
	PP2_BITFIELD_CLIENT_CERT_SESS uint8 = 0x04
)

const (
	// tlvSSLMinLen is the minimum length of a SSL TLV.
	tlvSSLMinLen = 5 // len(pp2_tlv_ssl.client) + len(pp2_tlv_ssl.verify)
)

// PP2SSL represents the PP2_TYPE_SSL TLV and its subtypes.
//
// See section 2.2.6 of the PROXY protocol spec.
/*
   struct pp2_tlv_ssl {
           uint8_t  client;
           uint32_t verify;
           struct pp2_tlv sub_tlv[0];
   };
*/
type PP2SSL struct {
	// The Client field is made of a bit field from the following values,
	// indicating which element is present: PP2_BITFIELD_CLIENT_SSL,
	// PP2_BITFIELD_CLIENT_CERT_CONN, PP2_BITFIELD_CLIENT_CERT_SESS
	Client uint8
	// Verify will be zero if the client presented a certificate
	// and it was successfully verified, and non-zero otherwise.
	Verify uint32
	TLV    []proxyproto.TLV
}

// Verified is true if the client presented a certificate and it was successfully verified.
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
		if tlv.Type == proxyproto.PP2_SUBTYPE_SSL_VERSION {
			return string(tlv.Value), true
		}
	}
	return "", false
}

// SSLCipher returns the US-ASCII string representation of the used TLS cipher and whether that extension exists.
func (s PP2SSL) SSLCipher() (string, bool) {
	for _, tlv := range s.TLV {
		if tlv.Type == proxyproto.PP2_SUBTYPE_SSL_CIPHER {
			return string(tlv.Value), true
		}
	}
	return "", false
}

// Marshal formats the PP2SSL structure as a TLV.
func (s PP2SSL) Marshal() (proxyproto.TLV, error) {
	v := make([]byte, 5)
	v[0] = s.Client
	binary.BigEndian.PutUint32(v[1:5], s.Verify)

	tlvs, err := proxyproto.JoinTLVs(s.TLV)
	if err != nil {
		return proxyproto.TLV{}, err
	}
	v = append(v, tlvs...)

	return proxyproto.TLV{
		Type:  proxyproto.PP2_TYPE_SSL,
		Value: v,
	}, nil
}

// ClientCN returns the string representation (in UTF8) of the Common Name field (OID: 2.5.4.3) of the client
// certificate's Distinguished Name and whether that extension exists.
func (s PP2SSL) ClientCN() (string, bool) {
	for _, tlv := range s.TLV {
		if tlv.Type == proxyproto.PP2_SUBTYPE_SSL_CN {
			return string(tlv.Value), true
		}
	}
	return "", false
}

// stringSubTLV returns the value of the first sub-TLV of the given type as a
// string and whether that sub-TLV exists.
func (s PP2SSL) stringSubTLV(typ proxyproto.PP2Type) (string, bool) {
	for _, tlv := range s.TLV {
		if tlv.Type == typ {
			return string(tlv.Value), true
		}
	}
	return "", false
}

// SSLSigAlg returns the US-ASCII string name of the algorithm used to sign the
// certificate presented by the frontend (PP2_SUBTYPE_SSL_SIG_ALG), for example
// "RSA-SHA256", and whether that extension exists.
func (s PP2SSL) SSLSigAlg() (string, bool) {
	return s.stringSubTLV(proxyproto.PP2_SUBTYPE_SSL_SIG_ALG)
}

// SSLKeyAlg returns the US-ASCII string name of the algorithm used to generate
// the key of the certificate presented by the frontend
// (PP2_SUBTYPE_SSL_KEY_ALG), for example "RSA2048", and whether that extension
// exists.
func (s PP2SSL) SSLKeyAlg() (string, bool) {
	return s.stringSubTLV(proxyproto.PP2_SUBTYPE_SSL_KEY_ALG)
}

// SSLGroup returns the US-ASCII string name of the key exchange algorithm used
// for the frontend TLS connection (PP2_SUBTYPE_SSL_GROUP), for example
// "secp256r1", and whether that extension exists.
func (s PP2SSL) SSLGroup() (string, bool) {
	return s.stringSubTLV(proxyproto.PP2_SUBTYPE_SSL_GROUP)
}

// SSLSigScheme returns the US-ASCII string name of the algorithm the frontend
// used to sign the ServerKeyExchange or CertificateVerify message
// (PP2_SUBTYPE_SSL_SIG_SCHEME), for example "rsa_pss_rsae_sha256", and whether
// that extension exists.
func (s PP2SSL) SSLSigScheme() (string, bool) {
	return s.stringSubTLV(proxyproto.PP2_SUBTYPE_SSL_SIG_SCHEME)
}

// ClientCert returns the raw X.509 client certificate encoded in ASN.1 DER and
// whether that extension exists.
func (s PP2SSL) ClientCert() ([]byte, bool) {
	for _, tlv := range s.TLV {
		if tlv.Type == proxyproto.PP2_SUBTYPE_SSL_CLIENT_CERT {
			return tlv.Value, true
		}
	}
	return nil, false
}

// IsSSL reports whether the TLV is of SSL type.
func IsSSL(t proxyproto.TLV) bool {
	return t.Type == proxyproto.PP2_TYPE_SSL && len(t.Value) >= tlvSSLMinLen
}

// SSL returns the pp2_tlv_ssl from section 2.2.6 or errors with ErrIncompatibleTLV or ErrMalformedTLV.
func SSL(t proxyproto.TLV) (PP2SSL, error) {
	ssl := PP2SSL{}
	if !IsSSL(t) {
		return ssl, proxyproto.ErrIncompatibleTLV
	}
	if len(t.Value) < tlvSSLMinLen {
		return ssl, proxyproto.ErrMalformedTLV
	}
	ssl.Client = t.Value[0]
	ssl.Verify = binary.BigEndian.Uint32(t.Value[1:5])
	var err error
	ssl.TLV, err = proxyproto.SplitTLVs(t.Value[5:])
	if err != nil {
		return PP2SSL{}, err
	}
	versionFound := !ssl.ClientSSL()
	for _, tlv := range ssl.TLV {
		switch tlv.Type {
		case proxyproto.PP2_SUBTYPE_SSL_VERSION:
			/*
				The PP2_CLIENT_SSL flag indicates that the client connected over SSL/TLS. When
				this field is present, the US-ASCII string representation of the TLS version is
				appended at the end of the field in the TLV format using the type
				PP2_SUBTYPE_SSL_VERSION.
			*/
			if len(tlv.Value) == 0 || !isASCII(tlv.Value) {
				return PP2SSL{}, proxyproto.ErrMalformedTLV
			}
			versionFound = true
		case proxyproto.PP2_SUBTYPE_SSL_CN:
			/*
				In all cases, the string representation (in UTF8) of the Common Name field
				(OID: 2.5.4.3) of the client certificate's Distinguished Name, is appended
				using the TLV format and the type PP2_SUBTYPE_SSL_CN. E.g. "example.com".
			*/
			if len(tlv.Value) == 0 || !utf8.Valid(tlv.Value) {
				return PP2SSL{}, proxyproto.ErrMalformedTLV
			}
		case proxyproto.PP2_SUBTYPE_SSL_CIPHER:
			/*
				The second level TLV PP2_SUBTYPE_SSL_CIPHER provides the US-ASCII string name
				of the used cipher, for example "ECDHE-RSA-AES128-GCM-SHA256".
			*/
			if len(tlv.Value) == 0 || !isASCII(tlv.Value) {
				return PP2SSL{}, proxyproto.ErrMalformedTLV
			}
		}
	}
	if !versionFound {
		return PP2SSL{}, proxyproto.ErrMalformedTLV
	}
	return ssl, nil
}

// FindSSL returns the first PP2SSL if it exists and is well formed.
func FindSSL(tlvs []proxyproto.TLV) (PP2SSL, bool) {
	for _, t := range tlvs {
		if ssl, err := SSL(t); err == nil {
			return ssl, true
		}
	}
	return PP2SSL{}, false
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
