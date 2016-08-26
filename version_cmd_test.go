package proxyproto

import (
	"testing"
)

func TestLocal(t *testing.T) {
	b := byte(LOCAL)
	if ProtocolVersionAndCommand(b).IsUnspec() {
		t.Fail()
	}
	if !ProtocolVersionAndCommand(b).IsLocal() {
		t.Fail()
	}
	if ProtocolVersionAndCommand(b).IsProxy() {
		t.Fail()
	}
	if ProtocolVersionAndCommand(b).toByte() != b {
		t.Fail()
	}
}

func TestProxy(t *testing.T) {
	b := byte(PROXY)
	if ProtocolVersionAndCommand(b).IsUnspec() {
		t.Fail()
	}
	if ProtocolVersionAndCommand(b).IsLocal() {
		t.Fail()
	}
	if !ProtocolVersionAndCommand(b).IsProxy() {
		t.Fail()
	}
	if ProtocolVersionAndCommand(b).toByte() != b {
		t.Fail()
	}
}

func TestInvalidProtocolVersion(t *testing.T) {
	if !ProtocolVersionAndCommand(0x00).IsUnspec() {
		t.Fail()
	}
}
