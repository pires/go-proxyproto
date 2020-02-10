package proxyproto

import "net"

// PolicyFunc can be used to decide whether to trust the PROXY info from
// upstream. If set, the connecting address is passed in as an argument.
//
// See below for the different policies.
//
// In case an error is returned the connection is denied.
type PolicyFunc func(upstream net.Addr) (Policy, error)

// Policy defines how a connection with a PROXY header address is treated.
type Policy int

const (
	// USE address from PROXY header
	USE Policy = iota
	// IGNORE address from PROXY header, but accept connection
	IGNORE
	// REJECT connection when PROXY header is sent
	// Note: even though the first read on the connection returns an error if
	// a PROXY header is present, subsequent reads do not. It is the task of
	// the code using the connection to handle that case properly.
	REJECT
	// REQUIRE connection to send PROXY header, reject if not present
	// Note: even though the first read on the connection returns an error if
	// a PROXY header is not present, subsequent reads do not. It is the task
	// of the code using the connection to handle that case properly.
	REQUIRE
)

// LaxWhiteListPolicy returns a PolicyFunc which decides whether the
// upstream ip is allowed to send a proxy header based on a list of allowed
// IP addresses. In case upstream IP is not in list the proxy header will
// be ignored.
func LaxWhiteListPolicy(allowed []string) PolicyFunc {
	return whitelistPolicy(allowed, IGNORE)
}

// StrictWhiteListPolicy returns a PolicyFunc which decides whether the
// upstream ip is allowed to send a proxy header based on a list of allowed
// IP addresses. In case upstream IP is not in list reading on the
// connection will be refused on the first read. Please note: subsequent
// reads do not error. It is the task of the code using the connection to
// handle that case properly.
func StrictWhiteListPolicy(allowed []string) PolicyFunc {
	return whitelistPolicy(allowed, REJECT)
}

func whitelistPolicy(allowed []string, def Policy) PolicyFunc {
	return func(upstream net.Addr) (Policy, error) {
		upstreamIP, _, err := net.SplitHostPort(upstream.String())
		if err != nil {
			// something is wrong with the source IP, better reject the connection
			return REJECT, err
		}

		for _, allowFrom := range allowed {
			if allowFrom == upstreamIP {
				return USE, nil
			}
		}

		return def, nil
	}
}

// WithPolicy adds given policy to a connection when passed as option to NewConn()
func WithPolicy(p Policy) func(*Conn) {
	return func(c *Conn) {
		c.proxyHeaderPolicy = p
	}
}
