// This file was shamefully stolen from github.com/armon/go-proxyproto.
// It has been heavily edited to conform to this lib.
//
// Thanks @armon
package proxyproto

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"testing"
)

func TestPassthrough(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{Listener: l}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		conn.Write([]byte("ping"))
		recv := make([]byte, 4)
		_, err = conn.Read(recv)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !bytes.Equal(recv, []byte("pong")) {
			t.Fatalf("bad: %v", recv)
		}
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestParse_ipv4(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{Listener: l}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Write out the header!
		header := &Header{
			Version:            2,
			Command:            PROXY,
			TransportProtocol:  TCPv4,
			SourceAddress:      net.ParseIP("10.1.1.1"),
			SourcePort:         1000,
			DestinationAddress: net.ParseIP("20.2.2.2"),
			DestinationPort:    2000,
		}
		header.WriteTo(conn)

		conn.Write([]byte("ping"))
		recv := make([]byte, 4)
		_, err = conn.Read(recv)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !bytes.Equal(recv, []byte("pong")) {
			t.Fatalf("bad: %v", recv)
		}
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the remote addr
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if addr.IP.String() != "10.1.1.1" {
		t.Fatalf("bad: %v", addr)
	}
	if addr.Port != 1000 {
		t.Fatalf("bad: %v", addr)
	}
}

func TestParse_ipv6(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	pl := &Listener{Listener: l}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Write out the header!
		header := &Header{
			Version:            2,
			Command:            PROXY,
			TransportProtocol:  TCPv6,
			SourceAddress:      net.ParseIP("ffff::ffff"),
			SourcePort:         1000,
			DestinationAddress: net.ParseIP("ffff::ffff"),
			DestinationPort:    2000,
		}
		header.WriteTo(conn)

		conn.Write([]byte("ping"))
		recv := make([]byte, 4)
		_, err = conn.Read(recv)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !bytes.Equal(recv, []byte("pong")) {
			t.Fatalf("bad: %v", recv)
		}
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the remote addr
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if addr.IP.String() != "ffff::ffff" {
		t.Fatalf("bad: %v", addr)
	}
	if addr.Port != 1000 {
		t.Fatalf("bad: %v", addr)
	}
}

func TestAcceptReturnsErrorWhenPolicyFuncErrors(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	expectedErr := fmt.Errorf("failure")
	policyFunc := func(upstream net.Addr) (Policy, error) { return USE, expectedErr }

	pl := &Listener{Listener: l, Policy: policyFunc}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()
	}()

	conn, err := pl.Accept()
	if err != expectedErr {
		t.Fatalf("Expected error %v, got %v", expectedErr, err)
	}

	if conn != nil {
		t.Fatalf("Expected no connection, got %v", conn)
	}
}

func TestReadingIsRefusedWhenProxyHeaderRequiredButMissing(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	policyFunc := func(upstream net.Addr) (Policy, error) { return REQUIRE, nil }

	pl := &Listener{Listener: l, Policy: policyFunc}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()
		conn.Write([]byte("ping"))
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != ErrNoProxyProtocol {
		t.Fatalf("Expected error %v, received %v", ErrNoProxyProtocol, err)
	}
}

func TestReadingIsRefusedWhenProxyHeaderPresentButNotAllowed(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	policyFunc := func(upstream net.Addr) (Policy, error) { return REJECT, nil }

	pl := &Listener{Listener: l, Policy: policyFunc}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()
		header := &Header{
			Version:            2,
			Command:            PROXY,
			TransportProtocol:  TCPv4,
			SourceAddress:      net.ParseIP("10.1.1.1"),
			SourcePort:         1000,
			DestinationAddress: net.ParseIP("20.2.2.2"),
			DestinationPort:    2000,
		}
		header.WriteTo(conn)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != ErrSuperfluousProxyHeader {
		t.Fatalf("Expected error %v, received %v", ErrSuperfluousProxyHeader, err)
	}
}
func TestIgnorePolicyIgnoresIpFromProxyHeader(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	policyFunc := func(upstream net.Addr) (Policy, error) { return IGNORE, nil }

	pl := &Listener{Listener: l, Policy: policyFunc}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Write out the header!
		header := &Header{
			Version:            2,
			Command:            PROXY,
			TransportProtocol:  TCPv4,
			SourceAddress:      net.ParseIP("10.1.1.1"),
			SourcePort:         1000,
			DestinationAddress: net.ParseIP("20.2.2.2"),
			DestinationPort:    2000,
		}
		header.WriteTo(conn)

		conn.Write([]byte("ping"))
		recv := make([]byte, 4)
		_, err = conn.Read(recv)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !bytes.Equal(recv, []byte("pong")) {
			t.Fatalf("bad: %v", recv)
		}
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the remote addr
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if addr.IP.String() != "127.0.0.1" {
		t.Fatalf("bad: %v", addr)
	}
}

func Test_AllOptionsAreRecognized(t *testing.T) {
	recognizedOpt1 := false
	opt1 := func(c *Conn) {
		recognizedOpt1 = true
	}

	recognizedOpt2 := false
	opt2 := func(c *Conn) {
		recognizedOpt2 = true
	}

	server, client := net.Pipe()
	defer func() {
		client.Close()
	}()

	c := NewConn(server, opt1, opt2)
	if !recognizedOpt1 {
		t.Error("Expected option 1 recognized")
	}

	if !recognizedOpt2 {
		t.Error("Expected option 2 recognized")
	}

	c.Close()
}

func TestReadingIsRefusedOnErrorWhenRemoteAddrRequestedFirst(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	policyFunc := func(upstream net.Addr) (Policy, error) { return REQUIRE, nil }

	pl := &Listener{Listener: l, Policy: policyFunc}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()
		conn.Write([]byte("ping"))
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	_ = conn.RemoteAddr()
	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != ErrNoProxyProtocol {
		t.Fatalf("Expected error %v, received %v", ErrNoProxyProtocol, err)
	}
}

func TestReadingIsRefusedOnErrorWhenLocalAddrRequestedFirst(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	policyFunc := func(upstream net.Addr) (Policy, error) { return REQUIRE, nil }

	pl := &Listener{Listener: l, Policy: policyFunc}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()
		conn.Write([]byte("ping"))
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	_ = conn.LocalAddr()
	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != ErrNoProxyProtocol {
		t.Fatalf("Expected error %v, received %v", ErrNoProxyProtocol, err)
	}
}

func Test_ConnectionErrorsWhenHeaderValidationFails(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	validationError := fmt.Errorf("failed to validate")
	pl := &Listener{Listener: l, ValidateHeader: func(*Header) error { return validationError }}

	go func() {
		conn, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Write out the header!
		header := &Header{
			Version:            2,
			Command:            PROXY,
			TransportProtocol:  TCPv4,
			SourceAddress:      net.ParseIP("10.1.1.1"),
			SourcePort:         1000,
			DestinationAddress: net.ParseIP("20.2.2.2"),
			DestinationPort:    2000,
		}
		header.WriteTo(conn)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != validationError {
		t.Fatalf("expected validation error, got %v", err)
	}
}

type TestTLSServer struct {
	Listener net.Listener

	// TLS is the optional TLS configuration, populated with a new config
	// after TLS is started. If set on an unstarted server before StartTLS
	// is called, existing fields are copied into the new config.
	TLS             *tls.Config
	TLSClientConfig *tls.Config

	// certificate is a parsed version of the TLS config certificate, if present.
	certificate *x509.Certificate
}

func (s *TestTLSServer) Addr() string {
	return s.Listener.Addr().String()
}

func (s *TestTLSServer) Close() {
	s.Listener.Close()
}

// based on net/http/httptest/Server.StartTLS
func NewTestTLSServer(l net.Listener) *TestTLSServer {
	s := &TestTLSServer{}

	cert, err := tls.X509KeyPair(LocalhostCert, LocalhostKey)
	if err != nil {
		panic(fmt.Sprintf("httptest: NewTLSServer: %v", err))
	}
	s.TLS = new(tls.Config)
	if len(s.TLS.Certificates) == 0 {
		s.TLS.Certificates = []tls.Certificate{cert}
	}
	s.certificate, err = x509.ParseCertificate(s.TLS.Certificates[0].Certificate[0])
	if err != nil {
		panic(fmt.Sprintf("NewTestTLSServer: %v", err))
	}
	certpool := x509.NewCertPool()
	certpool.AddCert(s.certificate)
	s.TLSClientConfig = &tls.Config{
		RootCAs: certpool,
	}
	s.Listener = tls.NewListener(l, s.TLS)

	return s
}

func Test_TLSServer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	s := NewTestTLSServer(l)
	s.Listener = &Listener{
		Listener: s.Listener,
		Policy: func(upstream net.Addr) (Policy, error) {
			return REQUIRE, nil
		},
	}
	defer s.Close()

	go func() {
		conn, err := tls.Dial("tcp", s.Addr(), s.TLSClientConfig)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Write out the header!
		header := &Header{
			Version:            2,
			Command:            PROXY,
			TransportProtocol:  TCPv4,
			SourceAddress:      net.ParseIP("10.1.1.1"),
			SourcePort:         1000,
			DestinationAddress: net.ParseIP("20.2.2.2"),
			DestinationPort:    2000,
		}
		header.WriteTo(conn)

		conn.Write([]byte("test"))
	}()

	conn, err := s.Listener.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 1024)
	n, err := conn.Read(recv)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if string(recv[:n]) != "test" {
		t.Fatalf("expected \"test\", got \"%s\" %v", recv[:n], recv[:n])
	}
}

func Test_MisconfiguredTLSServerRespondsWithUnderlyingError(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	s := NewTestTLSServer(l)
	s.Listener = &Listener{
		Listener: s.Listener,
		Policy: func(upstream net.Addr) (Policy, error) {
			return REQUIRE, nil
		},
	}
	defer s.Close()

	go func() {
		// this is not a valid TLS connection, we are
		// connecting to the TLS endpoint via plain TCP.
		//
		// it's an example of a configuration error:
		// client: HTTP  -> PROXY
		// server: PROXY -> TLS -> HTTP
		//
		// we want to bubble up the underlying error,
		// in this case a tls handshake error, instead
		// of responding with a non-descript
		// > "Proxy protocol signature not present".

		conn, err := net.Dial("tcp", s.Addr())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		// Write out the header!
		header := &Header{
			Version:            2,
			Command:            PROXY,
			TransportProtocol:  TCPv4,
			SourceAddress:      net.ParseIP("10.1.1.1"),
			SourcePort:         1000,
			DestinationAddress: net.ParseIP("20.2.2.2"),
			DestinationPort:    2000,
		}
		header.WriteTo(conn)

		conn.Write([]byte("GET /foo/bar HTTP/1.1"))
	}()

	conn, err := s.Listener.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 1024)
	_, err = conn.Read(recv)
	if err.Error() != "tls: first record does not look like a TLS handshake" {
		t.Fatalf("expected tls handshake error, got %s", err)
	}
}

// copied from src/net/http/internal/testcert.go

// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// LocalhostCert is a PEM-encoded TLS cert with SAN IPs
// "127.0.0.1" and "[::1]", expiring at Jan 29 16:00:00 2084 GMT.
// generated from src/crypto/tls:
// go run generate_cert.go  --rsa-bits 1024 --host 127.0.0.1,::1,example.com --ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
var LocalhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIICEzCCAXygAwIBAgIQMIMChMLGrR+QvmQvpwAU6zANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMCAXDTcwMDEwMTAwMDAwMFoYDzIwODQwMTI5MTYw
MDAwWjASMRAwDgYDVQQKEwdBY21lIENvMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB
iQKBgQDuLnQAI3mDgey3VBzWnB2L39JUU4txjeVE6myuDqkM/uGlfjb9SjY1bIw4
iA5sBBZzHi3z0h1YV8QPuxEbi4nW91IJm2gsvvZhIrCHS3l6afab4pZBl2+XsDul
rKBxKKtD1rGxlG4LjncdabFn9gvLZad2bSysqz/qTAUStTvqJQIDAQABo2gwZjAO
BgNVHQ8BAf8EBAMCAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUw
AwEB/zAuBgNVHREEJzAlggtleGFtcGxlLmNvbYcEfwAAAYcQAAAAAAAAAAAAAAAA
AAAAATANBgkqhkiG9w0BAQsFAAOBgQCEcetwO59EWk7WiJsG4x8SY+UIAA+flUI9
tyC4lNhbcF2Idq9greZwbYCqTTTr2XiRNSMLCOjKyI7ukPoPjo16ocHj+P3vZGfs
h1fIw3cSS2OolhloGw/XM6RWPWtPAlGykKLciQrBru5NAPvCMsb/I1DAceTiotQM
fblo6RBxUQ==
-----END CERTIFICATE-----`)

// LocalhostKey is the private key for localhostCert.
var LocalhostKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDuLnQAI3mDgey3VBzWnB2L39JUU4txjeVE6myuDqkM/uGlfjb9
SjY1bIw4iA5sBBZzHi3z0h1YV8QPuxEbi4nW91IJm2gsvvZhIrCHS3l6afab4pZB
l2+XsDulrKBxKKtD1rGxlG4LjncdabFn9gvLZad2bSysqz/qTAUStTvqJQIDAQAB
AoGAGRzwwir7XvBOAy5tM/uV6e+Zf6anZzus1s1Y1ClbjbE6HXbnWWF/wbZGOpet
3Zm4vD6MXc7jpTLryzTQIvVdfQbRc6+MUVeLKwZatTXtdZrhu+Jk7hx0nTPy8Jcb
uJqFk541aEw+mMogY/xEcfbWd6IOkp+4xqjlFLBEDytgbIECQQDvH/E6nk+hgN4H
qzzVtxxr397vWrjrIgPbJpQvBsafG7b0dA4AFjwVbFLmQcj2PprIMmPcQrooz8vp
jy4SHEg1AkEA/v13/5M47K9vCxmb8QeD/asydfsgS5TeuNi8DoUBEmiSJwma7FXY
fFUtxuvL7XvjwjN5B30pNEbc6Iuyt7y4MQJBAIt21su4b3sjXNueLKH85Q+phy2U
fQtuUE9txblTu14q3N7gHRZB4ZMhFYyDy8CKrN2cPg/Fvyt0Xlp/DoCzjA0CQQDU
y2ptGsuSmgUtWj3NM9xuwYPm+Z/F84K6+ARYiZ6PYj013sovGKUFfYAqVXVlxtIX
qyUBnu3X9ps8ZfjLZO7BAkEAlT4R5Yl6cGhaJQYZHOde3JEMhNRcVFMO8dJDaFeo
f9Oeos0UUothgiDktdQHxdNEwLjQf7lJJBzV+5OtwswCWA==
-----END RSA PRIVATE KEY-----`)
