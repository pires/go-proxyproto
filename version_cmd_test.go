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
	invalid := ProtocolVersionAndCommand(0x00)
	if !invalid.IsUnspec() {
		t.Fail()
	}
	// Unknown commands are serialized as LOCAL, which is the conservative v2
	// default because it carries no client address information.
	if invalid.toByte() != byte(LOCAL) {
		t.Fail()
	}
}
