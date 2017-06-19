package proxyproto

type v2header struct {
	*v1header

	Alpn      []byte
	Authority string

	SslClientBits     uint8
	SslClientSsl      bool
	SslClientCertConn bool
	SslClientCertSess bool
	SslVersion        string
	SslCn             string
	SslCipher         string
	SslSigAlg         string
	SslKeyAlg         string

	netNs string

	Custom     map[byte][]byte
	Experiment map[byte][]byte
}

func (header *v2header) Version() int {
	return 2
}
