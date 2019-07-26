package proxyproto

import (
	"net"
	"testing"
)

type failingAddr struct{}

func (f failingAddr) Network() string { return "failing" }
func (f failingAddr) String() string  { return "failing" }

func TestWhitelistPolicyReturnsErrorOnInvalidAddress(t *testing.T) {
	var cases = []struct {
		name   string
		policy PolicyFunc
	}{
		{"strict whitelist policy", StrictWhiteListPolicy([]string{"10.0.0.2", "10.0.0.3", "10.0.0.4"})},
		{"lax whitelist policy", LaxWhiteListPolicy([]string{"10.0.0.2", "10.0.0.3", "10.0.0.4"})},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.policy(failingAddr{})
			if err == nil {
				t.Fatal("Expected error, got none")
			}
		})
	}
}

func TestStrictWhitelistPolicyReturnsRejectWhenUpstreamIpAddrNotInWhitelist(t *testing.T) {
	p := StrictWhiteListPolicy([]string{"10.0.0.2", "10.0.0.3", "10.0.0.4"})

	upstream, err := net.ResolveTCPAddr("tcp", "10.0.0.5:45738")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	policy, err := p(upstream)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if policy != REJECT {
		t.Fatalf("Expected policy REJECT, got %v", policy)
	}
}

func TestLaxWhitelistPolicyReturnsIgnoreWhenUpstreamIpAddrNotInWhitelist(t *testing.T) {
	p := LaxWhiteListPolicy([]string{"10.0.0.2", "10.0.0.3", "10.0.0.4"})

	upstream, err := net.ResolveTCPAddr("tcp", "10.0.0.5:45738")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	policy, err := p(upstream)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if policy != IGNORE {
		t.Fatalf("Expected policy IGNORE, got %v", policy)
	}
}

func TestWhitelistPolicyReturnsUseWhenUpstreamIpAddrInWhitelist(t *testing.T) {
	var cases = []struct {
		name   string
		policy PolicyFunc
	}{
		{"strict whitelist policy", StrictWhiteListPolicy([]string{"10.0.0.2", "10.0.0.3", "10.0.0.4"})},
		{"lax whitelist policy", LaxWhiteListPolicy([]string{"10.0.0.2", "10.0.0.3", "10.0.0.4"})},
	}

	upstream, err := net.ResolveTCPAddr("tcp", "10.0.0.3:45738")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := tc.policy(upstream)
			if err != nil {
				t.Fatalf("err: %v", err)
			}

			if policy != USE {
				t.Fatalf("Expected policy USE, got %v", policy)
			}
		})
	}
}
