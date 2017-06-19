package proxyproto

import "net"

// v1header is the placeholder for proxy protocol header.
type v1header struct {
	command            ProtocolVersionAndCommand
	transportProtocol  AddressFamilyAndProtocol
	sourceAddress      net.IP
	destinationAddress net.IP
	sourcePort         uint16
	destinationPort    uint16
}

func (header *v1header) Version() int {
	return 1
}

func (header *v1header) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   header.sourceAddress,
		Port: int(header.sourcePort),
	}
}

func (header *v1header) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   header.destinationAddress,
		Port: int(header.destinationPort),
	}
}

func (header *v1header) Command() ProtocolVersionAndCommand {
	return header.command
}
