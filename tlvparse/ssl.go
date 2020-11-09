package tlvparse

import (
	"encoding/binary"
	"unicode"
	"unicode/utf8"

	"github.com/pires/go-proxyproto"
)

const (
	// pp2_tlv_ssl.client  bit fields
	PP2_BITFIELD_CLIENT_SSL       uint8 = 0x01
	PP2_BITFIELD_CLIENT_CERT_CONN       = 0x02
	PP2_BITFIELD_CLIENT_CERT_SESS       = 0x04

	tlvSSLMinLen = 5 // len(pp2_tlv_ssl.client) + len(pp2_tlv_ssl.verify)
)

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
	TLV []proxyproto.TLV
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
		if tlv.Type == proxyproto.PP2_SUBTYPE_SSL_VERSION {
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

// SSLType is true if the TLV is type SSL
func IsSSL(t proxyproto.TLV) bool {
	return t.Type == proxyproto.PP2_TYPE_SSL && len(t.Value) >= tlvSSLMinLen
}

// SSL returns the pp2_tlv_ssl from section 2.2.5 or errors with ErrIncompatibleTLV or ErrMalformedTLV
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
		}
	}
	if !versionFound {
		return PP2SSL{}, proxyproto.ErrMalformedTLV
	}
	return ssl, nil
}

// SSL returns the first PP2SSL if it exists and is well formed as well as bool indicating if it was found.
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
