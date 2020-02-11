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
		{"strict whitelist policy", MustStrictWhiteListPolicy([]string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.0/30"})},
		{"lax whitelist policy", MustLaxWhiteListPolicy([]string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.0/30"})},
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
	p := MustStrictWhiteListPolicy([]string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.0/30"})

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
	p := MustLaxWhiteListPolicy([]string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.0/30"})

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
		{"strict whitelist policy", MustStrictWhiteListPolicy([]string{"10.0.0.2", "10.0.0.3", "10.0.0.4"})},
		{"lax whitelist policy", MustLaxWhiteListPolicy([]string{"10.0.0.2", "10.0.0.3", "10.0.0.4"})},
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

func TestWhitelistPolicyReturnsUseWhenUpstreamIpAddrInWhitelistRange(t *testing.T) {
	var cases = []struct {
		name   string
		policy PolicyFunc
	}{
		{"strict whitelist policy", MustStrictWhiteListPolicy([]string{"10.0.0.0/29"})},
		{"lax whitelist policy", MustLaxWhiteListPolicy([]string{"10.0.0.0/29"})},
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

func Test_CreateWhitelistPolicyWithInvalidCidrReturnsError(t *testing.T) {
	_, err := StrictWhiteListPolicy([]string{"20/80"})
	if err == nil {
		t.Error("Expected error, got none")
	}
}

func Test_CreateWhitelistPolicyWithInvalidIpAddressReturnsError(t *testing.T) {
	_, err := StrictWhiteListPolicy([]string{"855.222.233.11"})
	if err == nil {
		t.Error("Expected error, got none")
	}
}

func Test_CreateLaxPolicyWithInvalidCidrReturnsError(t *testing.T) {
	_, err := LaxWhiteListPolicy([]string{"20/80"})
	if err == nil {
		t.Error("Expected error, got none")
	}
}

func Test_CreateLaxPolicyWithInvalidIpAddresseturnsError(t *testing.T) {
	_, err := LaxWhiteListPolicy([]string{"855.222.233.11"})
	if err == nil {
		t.Error("Expected error, got none")
	}
}

func Test_MustLaxWhiteListPolicyPanicsWithInvalidIpAddress(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected a panic, but got none")
		}
	}()

	MustLaxWhiteListPolicy([]string{"855.222.233.11"})
}

func Test_MustLaxWhiteListPolicyPanicsWithInvalidIpRange(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected a panic, but got none")
		}
	}()

	MustLaxWhiteListPolicy([]string{"20/80"})
}

func Test_MustStrictWhiteListPolicyPanicsWithInvalidIpAddress(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected a panic, but got none")
		}
	}()

	MustStrictWhiteListPolicy([]string{"855.222.233.11"})
}

func Test_MustStrictWhiteListPolicyPanicsWithInvalidIpRange(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected a panic, but got none")
		}
	}()

	MustStrictWhiteListPolicy([]string{"20/80"})
}
