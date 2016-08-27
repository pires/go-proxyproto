package proxyproto

import (
	"bufio"
	"net"
	"testing"
	"time"
)

// Stuff to be used in both versions tests.

const (
	NO_PROTOCOL = "There is no spoon"
	IP4_ADDR    = "127.0.0.1"
	IP6_ADDR    = "::1"
	PORT        = 65533
)

var (
	v4addr = net.ParseIP(IP4_ADDR).To4()
	v6addr = net.ParseIP(IP6_ADDR).To16()
)

type timeoutReader []byte

func (t *timeoutReader) Read([]byte) (int, error) {
	time.Sleep(500 * time.Millisecond)
	return 0, nil
}

func TestReadTimeoutV1Invalid(t *testing.T) {
	var b timeoutReader
	reader := bufio.NewReader(&b)
	_, err := ReadTimeout(reader, 50*time.Millisecond)
	if err == nil {
		t.Fatalf("TestReadTimeoutV1Invalid: expected error %s", ErrNoProxyProtocol)
	} else if err != ErrNoProxyProtocol {
		t.Fatalf("TestReadTimeoutV1Invalid: expected %s, actual %s", ErrNoProxyProtocol, err)
	}
}
