package proxyproto

import (
	"errors"
	"net"
	"testing"
)

const (
	// testWhitelistIP1, testWhitelistIP2 and testWhitelistIP3 are valid sample
	// IPs reused as the allowed set across whitelist-policy cases.
	testWhitelistIP1 = "10.0.0.2"
	testWhitelistIP2 = "10.0.0.3"
	testWhitelistIP3 = "10.0.0.4"
	// testWhitelistCIDR is a valid CIDR reused across whitelist-policy cases.
	testWhitelistCIDR = "10.0.0.0/30"
	// testMalformedCIDR and testMalformedIP are intentionally invalid inputs
	// reused across policy error-path cases.
	testMalformedCIDR = "20/80"
	testMalformedIP   = "855.222.233.11"
	// testWhitelistCIDRv6 is a valid IPv6 CIDR reused across policy cases.
	testWhitelistCIDRv6 = "2001:db8::/64"
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
		{"strict whitelist policy", MustStrictWhiteListPolicy([]string{testWhitelistIP1, testWhitelistIP2, testWhitelistIP3, testWhitelistCIDR})}, //nolint:goconst // test-case label, clearer inline
		{"lax whitelist policy", MustLaxWhiteListPolicy([]string{testWhitelistIP1, testWhitelistIP2, testWhitelistIP3, testWhitelistCIDR})},       //nolint:goconst // test-case label, clearer inline
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
		{"conn strict whitelist policy", ConnMustStrictWhiteListPolicy([]string{testWhitelistIP2})},
		{"conn lax whitelist policy", ConnMustLaxWhiteListPolicy([]string{testWhitelistIP2})},
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

func Test_CreateWhitelistPolicyWithInvalidCidrReturnsError(t *testing.T) {
	var cases = []struct {
		name string
		fn   func() error
	}{
		{"strict whitelist policy", func() error {
			_, err := StrictWhiteListPolicy([]string{testMalformedCIDR})
			return err
		}},
		{"lax whitelist policy", func() error {
			_, err := LaxWhiteListPolicy([]string{testMalformedCIDR})
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
			_, err := StrictWhiteListPolicy([]string{testMalformedIP})
			return err
		}},
		{"lax whitelist policy", func() error {
			_, err := LaxWhiteListPolicy([]string{testMalformedIP})
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
	tcpAddr := func(s string) net.Addr {
		addr, err := net.ResolveTCPAddr("tcp", s)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		return addr
	}

	var cases = []struct {
		name            string
		policy          ConnPolicyFunc
		allowed, denied net.Addr
		expectedUse     Policy
		expectedReject  Policy
	}{
		{"conn strict whitelist policy", ConnMustStrictWhiteListPolicy([]string{testWhitelistIP2}), tcpAddr("10.0.0.3:45738"), tcpAddr("10.0.0.4:45738"), USE, REJECT},
		{"conn lax whitelist policy", ConnMustLaxWhiteListPolicy([]string{testWhitelistIP2}), tcpAddr("10.0.0.3:45738"), tcpAddr("10.0.0.4:45738"), USE, IGNORE},
		{"conn strict whitelist IPv6 address", ConnMustStrictWhiteListPolicy([]string{"2001:db8::5"}), tcpAddr("[2001:db8::5]:45738"), tcpAddr("[2001:db8::6]:45738"), USE, REJECT},
		{"conn lax whitelist IPv6 CIDR", ConnMustLaxWhiteListPolicy([]string{testWhitelistCIDRv6}), tcpAddr("[2001:db8::17]:45738"), tcpAddr("[2001:db9::17]:45738"), USE, IGNORE},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allowed, denied := tc.allowed, tc.denied
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

	upstream6, err := net.ResolveTCPAddr("tcp", "[2001:db8::5]:45738")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Trusted sources must send a header (REQUIRE, never guessed); everything
	// else is dropped by Accept via an ErrInvalidUpstream-wrapping error.
	var cases = []struct {
		name           string
		policy         ConnPolicyFunc
		upstreamAddr   net.Addr
		expectedPolicy Policy
		expectError    bool
	}{
		{"drop connection from untrusted source", TrustProxyHeaderFrom(net.ParseIP("192.0.2.1")), upstream, REJECT, true},
		{"require header from trusted load balancer", TrustProxyHeaderFrom(net.ParseIP("10.0.0.3")), upstream, REQUIRE, false},
		{"require header when source matches any trusted IP", TrustProxyHeaderFrom(net.ParseIP("192.0.2.1"), net.ParseIP("10.0.0.3")), upstream, REQUIRE, false},
		{"require header from trusted IPv6 source", TrustProxyHeaderFrom(net.ParseIP("2001:db8::5")), upstream6, REQUIRE, false},
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
			if tc.expectError && !errors.Is(err, ErrInvalidUpstream) {
				t.Fatalf("expected an ErrInvalidUpstream-wrapping error, got %v", err)
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

// TestBuiltinPoliciesWrapAddrErrorsAsInvalidUpstream pins the policy error
// contract: when a built-in policy cannot classify the peer address (e.g. a
// Unix socket address with no host:port), the returned error must wrap
// ErrInvalidUpstream so Listener.Accept drops that connection and keeps
// listening, rather than surfacing the error and stopping the accept loop.
func TestBuiltinPoliciesWrapAddrErrorsAsInvalidUpstream(t *testing.T) {
	unixAddr := &net.UnixAddr{Name: "/tmp/app.sock", Net: "unix"}
	opts := ConnPolicyOptions{Upstream: unixAddr, Downstream: unixAddr}

	_, cidr, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	whitelist, err := ConnLaxWhiteListPolicy([]string{testWhitelistIP1})
	if err != nil {
		t.Fatal(err)
	}

	trustRanges, err := TrustProxyHeaderFromRanges([]string{testWhitelistCIDR})
	if err != nil {
		t.Fatal(err)
	}

	policies := map[string]ConnPolicyFunc{
		"ConnSkipProxyHeaderForCIDR":      ConnSkipProxyHeaderForCIDR(cidr, USE),
		"ConnLaxWhiteListPolicy":          whitelist,
		"PolicyFromRanges":                MustPolicyFromRanges([]string{testWhitelistCIDR}, USE, IGNORE),
		"TrustProxyHeaderFrom":            TrustProxyHeaderFrom(net.ParseIP(testWhitelistIP1)),
		"TrustProxyHeaderFromRanges":      trustRanges,
		"IgnoreProxyHeaderNotOnInterface": IgnoreProxyHeaderNotOnInterface(net.ParseIP(testWhitelistIP1)),
	}
	for name, policy := range policies {
		if _, err := policy(opts); !errors.Is(err, ErrInvalidUpstream) {
			t.Errorf("%s: error must wrap ErrInvalidUpstream, got %v", name, err)
		}
	}
}

// TestWhiteListPolicyFuncs covers the deprecated PolicyFunc wrappers across the
// whole decision matrix (IP match, CIDR match, and miss, under strict and lax
// flavors); the ConnPolicyFunc equivalents are covered by
// TestConnWhitelistPolicies.
func TestWhiteListPolicyFuncs(t *testing.T) {
	addr := func(s string) net.Addr {
		a, err := net.ResolveTCPAddr("tcp", s)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		return a
	}
	list := []string{testWhitelistIP2, testWhitelistCIDR}

	cases := []struct {
		name     string
		policy   PolicyFunc
		upstream net.Addr
		want     Policy
	}{
		{"strict allows whitelisted IP", MustStrictWhiteListPolicy(list), addr("10.0.0.3:45738"), USE},
		{"strict allows IP inside CIDR", MustStrictWhiteListPolicy(list), addr("10.0.0.1:45738"), USE},
		{"strict rejects unlisted IP", MustStrictWhiteListPolicy(list), addr("10.0.0.5:45738"), REJECT},
		{"lax allows whitelisted IP", MustLaxWhiteListPolicy(list), addr("10.0.0.3:45738"), USE},
		{"lax allows IP inside CIDR", MustLaxWhiteListPolicy(list), addr("10.0.0.1:45738"), USE},
		{"lax ignores unlisted IP", MustLaxWhiteListPolicy(list), addr("10.0.0.5:45738"), IGNORE},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := tc.policy(tc.upstream)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if policy != tc.want {
				t.Fatalf("Expected policy %v, got %v", tc.want, policy)
			}
		})
	}
}

// TestMustWhiteListPolicyPanicsOnInvalidInput covers every Must* constructor
// (deprecated and Conn flavors) against malformed IPs and CIDRs.
func TestMustWhiteListPolicyPanicsOnInvalidInput(t *testing.T) {
	cases := []struct {
		name string
		fn   func()
	}{
		{"lax invalid IP", func() { MustLaxWhiteListPolicy([]string{testMalformedIP}) }},
		{"lax invalid CIDR", func() { MustLaxWhiteListPolicy([]string{testMalformedCIDR}) }},
		{"strict invalid IP", func() { MustStrictWhiteListPolicy([]string{testMalformedIP}) }},
		{"strict invalid CIDR", func() { MustStrictWhiteListPolicy([]string{testMalformedCIDR}) }},
		{"conn lax invalid IP", func() { ConnMustLaxWhiteListPolicy([]string{testMalformedIP}) }},
		{"conn strict invalid CIDR", func() { ConnMustStrictWhiteListPolicy([]string{testMalformedCIDR}) }},
		{"policy from ranges invalid IP", func() { MustPolicyFromRanges([]string{testMalformedIP}, USE, IGNORE) }},
		{"policy from ranges invalid CIDR", func() { MustPolicyFromRanges([]string{testMalformedCIDR}, REQUIRE, IGNORE) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Error("Expected a panic, but got none")
				}
			}()
			tc.fn()
		})
	}
}

// TestTrustProxyHeaderFromRanges pins the CIDR-capable strict helper: trusted
// sources (by IP or CIDR, v4 or v6) must send a header (REQUIRE), everything
// else is dropped via an ErrInvalidUpstream-wrapping error, and malformed
// input fails construction.
func TestTrustProxyHeaderFromRanges(t *testing.T) {
	addr := func(s string) net.Addr {
		a, err := net.ResolveTCPAddr("tcp", s)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		return a
	}

	policy, err := TrustProxyHeaderFromRanges([]string{"10.0.0.10", "192.0.2.0/24", testWhitelistCIDRv6})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	cases := []struct {
		name     string
		upstream net.Addr
		want     Policy
		wantErr  bool
	}{
		{"trusted individual IP", addr("10.0.0.10:45738"), REQUIRE, false},
		{"trusted IPv4 CIDR", addr("192.0.2.200:45738"), REQUIRE, false},
		{"trusted IPv6 CIDR", addr("[2001:db8::17]:45738"), REQUIRE, false},
		{"untrusted IP is dropped", addr("10.0.0.11:45738"), REJECT, true},
		{"untrusted IPv6 is dropped", addr("[2001:db9::17]:45738"), REJECT, true},
		{"unclassifiable address is dropped", failingAddr{}, REJECT, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := policy(ConnPolicyOptions{Upstream: tc.upstream})
			if tc.wantErr && !errors.Is(err, ErrInvalidUpstream) {
				t.Fatalf("expected an ErrInvalidUpstream-wrapping error, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("err: %v", err)
			}
			if got != tc.want {
				t.Fatalf("Expected policy %v, got %v", tc.want, got)
			}
		})
	}

	for _, bad := range []string{testMalformedIP, testMalformedCIDR} {
		if _, err := TrustProxyHeaderFromRanges([]string{bad}); err == nil {
			t.Errorf("expected a construction error for %q", bad)
		}
	}
}

// TestPolicyFromRanges pins the explicit range combinator across the
// combinations the deprecated *WhiteListPolicy helpers used to hide, plus the
// mixed-traffic combination they could not express.
func TestPolicyFromRanges(t *testing.T) {
	addr := func(s string) net.Addr {
		a, err := net.ResolveTCPAddr("tcp", s)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		return a
	}
	ranges := []string{testWhitelistIP2, "192.0.2.0/24", testWhitelistCIDRv6}

	cases := []struct {
		name               string
		matched, unmatched Policy
		upstream           net.Addr
		want               Policy
	}{
		{"lax equivalent, matched IP", USE, IGNORE, addr("10.0.0.3:45738"), USE},
		{"lax equivalent, unmatched", USE, IGNORE, addr("10.0.0.5:45738"), IGNORE},
		{"strict equivalent, matched CIDR", USE, REJECT, addr("192.0.2.7:45738"), USE},
		{"strict equivalent, unmatched", USE, REJECT, addr("10.0.0.5:45738"), REJECT},
		{"mixed traffic, matched v6 CIDR must send header", REQUIRE, IGNORE, addr("[2001:db8::17]:45738"), REQUIRE},
		{"mixed traffic, unmatched served raw", REQUIRE, IGNORE, addr("10.0.0.5:45738"), IGNORE},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := PolicyFromRanges(ranges, tc.matched, tc.unmatched)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			got, err := policy(ConnPolicyOptions{Upstream: tc.upstream})
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if got != tc.want {
				t.Fatalf("Expected policy %v, got %v", tc.want, got)
			}
		})
	}

	t.Run("unclassifiable address is dropped", func(t *testing.T) {
		policy, err := PolicyFromRanges(ranges, USE, IGNORE)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if _, err := policy(ConnPolicyOptions{Upstream: failingAddr{}}); !errors.Is(err, ErrInvalidUpstream) {
			t.Fatalf("expected an ErrInvalidUpstream-wrapping error, got %v", err)
		}
	})

	for _, bad := range []string{testMalformedIP, testMalformedCIDR} {
		if _, err := PolicyFromRanges([]string{bad}, USE, IGNORE); err == nil {
			t.Errorf("expected a construction error for %q", bad)
		}
	}
}
