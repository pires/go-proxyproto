package proxyproto

import (
	"net"
	"testing"
)

type failingAddr struct{}

func (f failingAddr) Network() string { return "failing" }
func (f failingAddr) String() string  { return "failing" }

type invalidIPAddr struct{}

func (i invalidIPAddr) Network() string { return "tcp" }
func (i invalidIPAddr) String() string  { return "999.999.999.999:1234" }

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

func TestWhitelistPolicyReturnsErrorOnInvalidIP(t *testing.T) {
	policies := []struct {
		name   string
		policy ConnPolicyFunc
	}{
		{"conn strict whitelist policy", ConnMustStrictWhiteListPolicy([]string{"10.0.0.3"})},
		{"conn lax whitelist policy", ConnMustLaxWhiteListPolicy([]string{"10.0.0.3"})},
	}

	for _, tc := range policies {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.policy(ConnPolicyOptions{Upstream: invalidIPAddr{}})
			if err == nil {
				t.Fatal("Expected error, got none")
			}
		})
	}
}

func TestStrictWhitelistPolicyReturnsRejectWhenUpstreamIpAddrNotInWhitelist(t *testing.T) {
	var cases = []struct {
		name   string
		policy PolicyFunc
	}{
		{"strict whitelist policy", MustStrictWhiteListPolicy([]string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.0/30"})},
	}

	upstream, err := net.ResolveTCPAddr("tcp", "10.0.0.5:45738")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := tc.policy(upstream)
			if err != nil {
				t.Fatalf("err: %v", err)
			}

			if policy != REJECT {
				t.Fatalf("Expected policy REJECT, got %v", policy)
			}
		})
	}
}

func TestLaxWhitelistPolicyReturnsIgnoreWhenUpstreamIpAddrNotInWhitelist(t *testing.T) {
	var cases = []struct {
		name   string
		policy PolicyFunc
	}{
		{"lax whitelist policy", MustLaxWhiteListPolicy([]string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.0/30"})},
	}

	upstream, err := net.ResolveTCPAddr("tcp", "10.0.0.5:45738")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := tc.policy(upstream)
			if err != nil {
				t.Fatalf("err: %v", err)
			}

			if policy != IGNORE {
				t.Fatalf("Expected policy IGNORE, got %v", policy)
			}
		})
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
	var cases = []struct {
		name string
		fn   func() error
	}{
		{"strict whitelist policy", func() error {
			_, err := StrictWhiteListPolicy([]string{"20/80"})
			return err
		}},
		{"lax whitelist policy", func() error {
			_, err := LaxWhiteListPolicy([]string{"20/80"})
			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.fn(); err == nil {
				t.Error("Expected error, got none")
			}
		})
	}
}

func Test_CreateWhitelistPolicyWithInvalidIpAddressReturnsError(t *testing.T) {
	var cases = []struct {
		name string
		fn   func() error
	}{
		{"strict whitelist policy", func() error {
			_, err := StrictWhiteListPolicy([]string{"855.222.233.11"})
			return err
		}},
		{"lax whitelist policy", func() error {
			_, err := LaxWhiteListPolicy([]string{"855.222.233.11"})
			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.fn(); err == nil {
				t.Error("Expected error, got none")
			}
		})
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

func TestWhiteListPolicyFuncsReturnPolicies(t *testing.T) {
	strictPolicy, err := StrictWhiteListPolicy([]string{"10.0.0.3"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	laxPolicy, err := LaxWhiteListPolicy([]string{"10.0.0.3"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	upstream, err := net.ResolveTCPAddr("tcp", "10.0.0.3:45738")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	policy, err := strictPolicy(upstream)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if policy != USE {
		t.Fatalf("Expected policy USE, got %v", policy)
	}

	policy, err = laxPolicy(upstream)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if policy != USE {
		t.Fatalf("Expected policy USE, got %v", policy)
	}
}

func TestSkipProxyHeaderForCIDR(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("192.0.2.1/24")
	f := SkipProxyHeaderForCIDR(cidr, REJECT)

	upstream, _ := net.ResolveTCPAddr("tcp", "192.0.2.255:12345")
	policy, err := f(upstream)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if policy != SKIP {
		t.Errorf("Expected a SKIP policy for the %s address", upstream)
	}

	upstream, _ = net.ResolveTCPAddr("tcp", "8.8.8.8:12345")
	policy, err = f(upstream)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if policy != REJECT {
		t.Errorf("Expected a REJECT policy for the %s address", upstream)
	}
}

func TestConnSkipProxyHeaderForCIDRReturnsErrorOnInvalidAddress(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("192.0.2.1/24")
	policy := ConnSkipProxyHeaderForCIDR(cidr, IGNORE)

	result, err := policy(ConnPolicyOptions{Upstream: failingAddr{}})
	if err == nil {
		t.Fatal("Expected error, got none")
	}
	if result != IGNORE {
		t.Fatalf("Expected policy IGNORE, got %v", result)
	}
}

func TestConnSkipProxyHeaderForCIDR(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("192.0.2.1/24")
	policy := ConnSkipProxyHeaderForCIDR(cidr, REJECT)

	upstream, _ := net.ResolveTCPAddr("tcp", "192.0.2.255:12345")
	result, err := policy(ConnPolicyOptions{Upstream: upstream})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if result != SKIP {
		t.Errorf("Expected a SKIP policy for the %s address", upstream)
	}

	upstream, _ = net.ResolveTCPAddr("tcp", "8.8.8.8:12345")
	result, err = policy(ConnPolicyOptions{Upstream: upstream})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if result != REJECT {
		t.Errorf("Expected a REJECT policy for the %s address", upstream)
	}
}

func TestConnWhitelistPolicies(t *testing.T) {
	var cases = []struct {
		name           string
		policy         ConnPolicyFunc
		expectedUse    Policy
		expectedReject Policy
	}{
		{"conn strict whitelist policy", ConnMustStrictWhiteListPolicy([]string{"10.0.0.3"}), USE, REJECT},
		{"conn lax whitelist policy", ConnMustLaxWhiteListPolicy([]string{"10.0.0.3"}), USE, IGNORE},
	}

	allowed, err := net.ResolveTCPAddr("tcp", "10.0.0.3:45738")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	denied, err := net.ResolveTCPAddr("tcp", "10.0.0.4:45738")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := tc.policy(ConnPolicyOptions{Upstream: allowed})
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if policy != tc.expectedUse {
				t.Fatalf("Expected policy %v, got %v", tc.expectedUse, policy)
			}

			policy, err = tc.policy(ConnPolicyOptions{Upstream: denied})
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if policy != tc.expectedReject {
				t.Fatalf("Expected policy %v, got %v", tc.expectedReject, policy)
			}
		})
	}
}

func TestTrustProxyHeaderFrom(t *testing.T) {
	upstream, err := net.ResolveTCPAddr("tcp", "10.0.0.3:45738")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	var cases = []struct {
		name           string
		policy         ConnPolicyFunc
		upstreamAddr   net.Addr
		expectedPolicy Policy
		expectError    bool
	}{
		{"reject header from untrusted source", TrustProxyHeaderFrom(net.ParseIP("192.0.2.1")), upstream, REJECT, false},
		{"use header from trusted load balancer", TrustProxyHeaderFrom(net.ParseIP("10.0.0.3")), upstream, USE, false},
		{"use header when source matches any trusted IP", TrustProxyHeaderFrom(net.ParseIP("192.0.2.1"), net.ParseIP("10.0.0.3")), upstream, USE, false},
		{"invalid address should return error", TrustProxyHeaderFrom(net.ParseIP("10.0.0.3")), failingAddr{}, REJECT, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := tc.policy(ConnPolicyOptions{
				Upstream: tc.upstreamAddr,
			})
			if !tc.expectError && err != nil {
				t.Fatalf("err: %v", err)
			}
			if tc.expectError && err == nil {
				t.Fatal("Expected error, got none")
			}

			if policy != tc.expectedPolicy {
				t.Fatalf("Expected policy %v, got %v", tc.expectedPolicy, policy)
			}
		})
	}
}

func TestIgnoreProxyHeaderNotOnInterface(t *testing.T) {
	downstream, err := net.ResolveTCPAddr("tcp", "10.0.0.3:45738")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	var cases = []struct {
		name              string
		policy            ConnPolicyFunc
		downstreamAddress net.Addr
		expectedPolicy    Policy
		expectError       bool
	}{
		{"ignore header for requests not on interface", IgnoreProxyHeaderNotOnInterface(net.ParseIP("192.0.2.1")), downstream, IGNORE, false},
		{"use headers for requests on interface", IgnoreProxyHeaderNotOnInterface(net.ParseIP("10.0.0.3")), downstream, USE, false},
		{"invalid address should return error", IgnoreProxyHeaderNotOnInterface(net.ParseIP("10.0.0.3")), failingAddr{}, REJECT, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := tc.policy(ConnPolicyOptions{
				Downstream: tc.downstreamAddress,
			})
			if !tc.expectError && err != nil {
				t.Fatalf("err: %v", err)
			}
			if tc.expectError && err == nil {
				t.Fatal("Expected error, got none")
			}

			if policy != tc.expectedPolicy {
				t.Fatalf("Expected policy %v, got %v", tc.expectedPolicy, policy)
			}
		})
	}
}
