package proxyproto

import "net"

// Stuff to be used in both versions tests.

const (
	NO_PROTOCOL = "There is no spoon"
	IP4_ADDR    = "127.0.0.1"
	IP6_ADDR    = "::1"
	PORT        = 65533
)

var (
	v4addr, _ = net.ResolveIPAddr(INET4, IP4_ADDR)
	v6addr, _ = net.ResolveIPAddr(INET6, IP6_ADDR)
)
