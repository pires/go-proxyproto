package proxyproto

import (
	"bufio"
	"bytes"
	"net"
	"strconv"
	"strings"
)

const (
	CRLF      = "\r\n"
	SEPARATOR = " "
)

func initVersion1() *v1header {
	header := new(v1header)
	// command doesn't exist in v1
	header.command = PROXY
	return header
}

func parseVersion1(reader *bufio.Reader) (*v1header, error) {
	// Make sure we have a v1 header
	line, err := reader.ReadString('\n')
	if !strings.HasSuffix(line, CRLF) {
		return nil, ErrCantReadProtocolVersionAndCommand
	}
	tokens := strings.Split(line[:len(line)-2], SEPARATOR)
	if len(tokens) < 6 {
		return nil, ErrCantReadProtocolVersionAndCommand
	}

	header := initVersion1()

	// Read address family and protocol
	switch tokens[1] {
	case "TCP4":
		header.transportProtocol = TCPv4
	case "TCP6":
		header.transportProtocol = TCPv6
	default:
		header.transportProtocol = UNSPEC
	}

	// Read addresses and ports
	header.sourceAddress, err = parseV1IPAddress(header.transportProtocol, tokens[2])
	if err != nil {
		return nil, err
	}
	header.destinationAddress, err = parseV1IPAddress(header.transportProtocol, tokens[3])
	if err != nil {
		return nil, err
	}
	header.sourcePort, err = parseV1PortNumber(tokens[4])
	if err != nil {
		return nil, err
	}
	header.destinationPort, err = parseV1PortNumber(tokens[5])
	if err != nil {
		return nil, err
	}
	return header, nil
}

func (header *v1header) Format() ([]byte, error) {
	// As of version 1, only "TCP4" ( \x54 \x43 \x50 \x34 ) for TCP over IPv4,
	// and "TCP6" ( \x54 \x43 \x50 \x36 ) for TCP over IPv6 are allowed.
	proto := "UNKNOWN"
	if header.transportProtocol == TCPv4 {
		proto = "TCP4"
	} else if header.transportProtocol == TCPv6 {
		proto = "TCP6"
	}

	var buf bytes.Buffer
	buf.Write(SIGV1)
	buf.WriteString(SEPARATOR)
	buf.WriteString(proto)
	buf.WriteString(SEPARATOR)
	buf.WriteString(header.sourceAddress.String())
	buf.WriteString(SEPARATOR)
	buf.WriteString(header.destinationAddress.String())
	buf.WriteString(SEPARATOR)
	buf.WriteString(strconv.Itoa(int(header.sourcePort)))
	buf.WriteString(SEPARATOR)
	buf.WriteString(strconv.Itoa(int(header.destinationPort)))
	buf.WriteString(CRLF)

	return buf.Bytes(), nil
}

func parseV1PortNumber(portStr string) (uint16, error) {
	var port uint16

	_port, err := strconv.Atoi(portStr)
	if err == nil {
		if port < 0 || port > 65535 {
			err = ErrInvalidPortNumber
		}
		port = uint16(_port)
	}

	return port, err
}

func parseV1IPAddress(protocol AddressFamilyAndProtocol, addrStr string) (addr net.IP, err error) {
	addr = net.ParseIP(addrStr)
	tryV4 := addr.To4()
	if (protocol == TCPv4 && tryV4 == nil) || (protocol == TCPv6 && tryV4 != nil) {
		err = ErrInvalidAddress
	}
	return
}
