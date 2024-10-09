// Package proxyproto implements Proxy Protocol (v1 and v2) parser and writer, as per specification:
// https://www.haproxy.org/download/2.3/doc/proxy-protocol.txt
package proxyproto

import "net"

func isIPv4(ip net.IP) bool {
	return ip.To4() != nil
}

func isIPv6(ip net.IP) bool {
	return ip.To16() != nil && !isIPv4(ip)
}
