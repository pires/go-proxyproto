package proxyproto

import (
	"testing"
)

func TestTCPoverIPv4(t *testing.T) {
	b := byte(TCPv4)
	if !AddressFamilyAndProtocol(b).IsIPv4() {
		t.Fail()
	}
	if !AddressFamilyAndProtocol(b).IsStream() {
		t.Fail()
	}
	if AddressFamilyAndProtocol(b).toByte() != b {
		t.Fail()
	}
}

func TestTCPoverIPv6(t *testing.T) {
	b := byte(TCPv6)
	if !AddressFamilyAndProtocol(b).IsIPv6() {
		t.Fail()
	}
	if !AddressFamilyAndProtocol(b).IsStream() {
		t.Fail()
	}
	if AddressFamilyAndProtocol(b).toByte() != b {
		t.Fail()
	}
}

func TestUDPoverIPv4(t *testing.T) {
	b := byte(UDPv4)
	if !AddressFamilyAndProtocol(b).IsIPv4() {
		t.Fail()
	}
	if !AddressFamilyAndProtocol(b).IsDatagram() {
		t.Fail()
	}
	if AddressFamilyAndProtocol(b).toByte() != b {
		t.Fail()
	}
}

func TestUDPoverIPv6(t *testing.T) {
	b := byte(UDPv6)
	if !AddressFamilyAndProtocol(b).IsIPv6() {
		t.Fail()
	}
	if !AddressFamilyAndProtocol(b).IsDatagram() {
		t.Fail()
	}
	if AddressFamilyAndProtocol(b).toByte() != b {
		t.Fail()
	}
}

func TestUnixStream(t *testing.T) {
	b := byte(UnixStream)
	if !AddressFamilyAndProtocol(b).IsUnix() {
		t.Fail()
	}
	if !AddressFamilyAndProtocol(b).IsStream() {
		t.Fail()
	}
	if AddressFamilyAndProtocol(b).toByte() != b {
		t.Fail()
	}
}

func TestUnixDatagram(t *testing.T) {
	b := byte(UnixDatagram)
	if !AddressFamilyAndProtocol(b).IsUnix() {
		t.Fail()
	}
	if !AddressFamilyAndProtocol(b).IsDatagram() {
		t.Fail()
	}
	if AddressFamilyAndProtocol(b).toByte() != b {
		t.Fail()
	}
}

func TestInvalidAddressFamilyAndProtocol(t *testing.T) {
	b := byte(UNSPEC)
	if !AddressFamilyAndProtocol(b).IsUnspec() {
		t.Fail()
	}
	if AddressFamilyAndProtocol(b).toByte() != b {
		t.Fail()
	}
}
