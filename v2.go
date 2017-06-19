package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	v2HeaderLen = 16

	v2AddrLenUnspec = 0
	v2AddrLenInet   = (4 + 4 + 2 + 2)
	v2AddrLenInet6  = (16 + 16 + 2 + 2)
	v2AddrLenUnix   = (108 + 108)

	v2TlvHeaderLen = 3

	v2TlvTypeAlpn          = 0x01
	v2TlvTypeAuthority     = 0x02
	v2TlvTypeCrc32c        = 0x03
	v2TlvTypeNoop          = 0x04
	v2TlvTypeSsl           = 0x20
	v2TlvSubtypeSslVersion = 0x21
	v2TlvSubtypeSslCn      = 0x22
	v2TlvSubtypeSslCipher  = 0x23
	v2TlvSubtypeSslSigAlg  = 0x24
	v2TlvSubtypeSslKeyAlg  = 0x25
	v2TlvTypeNetNs         = 0x30

	v2TlvTypeCustom0  = 0xE0
	v2TlvTypeCustom1  = 0xE1
	v2TlvTypeCustom2  = 0xE2
	v2TlvTypeCustom3  = 0xE3
	v2TlvTypeCustom4  = 0xE4
	v2TlvTypeCustom5  = 0xE5
	v2TlvTypeCustom6  = 0xE6
	v2TlvTypeCustom7  = 0xE7
	v2TlvTypeCustom8  = 0xE8
	v2TlvTypeCustom9  = 0xE9
	v2TlvTypeCustom10 = 0xEA
	v2TlvTypeCustom11 = 0xEB
	v2TlvTypeCustom12 = 0xEC
	v2TlvTypeCustom13 = 0xED
	v2TlvTypeCustom14 = 0xEE
	v2TlvTypeCustom15 = 0xEF

	v2TlvTypeExperiment0 = 0xF0
	v2TlvTypeExperiment1 = 0xF1
	v2TlvTypeExperiment2 = 0xF2
	v2TlvTypeExperiment3 = 0xF3
	v2TlvTypeExperiment4 = 0xF4
	v2TlvTypeExperiment5 = 0xF5
	v2TlvTypeExperiment6 = 0xF6
	v2TlvTypeExperiment7 = 0xF7
)

var (
	lengthV4Bytes = func() []byte {
		a := make([]byte, 2)
		binary.BigEndian.PutUint16(a, v2AddrLenInet)
		return a
	}()
	lengthV6Bytes = func() []byte {
		a := make([]byte, 2)
		binary.BigEndian.PutUint16(a, v2AddrLenInet6)
		return a
	}()
	lengthUnixBytes = func() []byte {
		a := make([]byte, 2)
		binary.BigEndian.PutUint16(a, v2AddrLenUnix) // was 218, but may've been wrong?
		return a
	}()
)

type _ports struct {
	SrcPort uint16
	DstPort uint16
}

type _addr4 struct {
	Src     [4]byte
	Dst     [4]byte
	SrcPort uint16
	DstPort uint16
}

type _addr6 struct {
	Src [16]byte
	Dst [16]byte
	_ports
}

type _addrUnix struct {
	Src [108]byte
	Dst [108]byte
}

func parseVersion2(reader *bufio.Reader) (header *v2header, err error) {
	// Skip first 12 bytes (signature)
	for i := 0; i < 12; i++ {
		if _, err = reader.ReadByte(); err != nil {
			return nil, ErrCantReadProtocolVersionAndCommand
		}
	}

	header = &v2header{
		v1header:   &v1header{},
		Custom:     make(map[byte][]byte, 0),
		Experiment: make(map[byte][]byte, 0),
	}

	// Read the 13th byte, protocol version and command
	b13, err := reader.ReadByte()
	if err != nil {
		return nil, ErrCantReadProtocolVersionAndCommand
	}
	header.command = ProtocolVersionAndCommand(b13)
	if _, ok := supportedCommand[header.command]; !ok {
		return nil, ErrUnsupportedProtocolVersionAndCommand
	}
	// If command is LOCAL, header ends here
	if header.command.IsLocal() {
		return header, nil
	}

	// Read the 14th byte, address family and protocol
	b14, err := reader.ReadByte()
	if err != nil {
		return nil, ErrCantReadAddressFamilyAndProtocol
	}
	header.transportProtocol = AddressFamilyAndProtocol(b14)
	if _, ok := supportedTransportProtocol[header.transportProtocol]; !ok {
		return nil, ErrUnsupportedAddressFamilyAndProtocol
	}

	// Make sure there are bytes available as specified in length
	var length uint16
	if err := binary.Read(io.LimitReader(reader, 2), binary.BigEndian, &length); err != nil {
		return nil, ErrCantReadLength
	}
	if !header.validateLength(length) {
		return nil, ErrInvalidLength
	}

	if _, err := reader.Peek(int(length)); err != nil {
		return nil, ErrInvalidLength
	}

	var tlvLength uint16

	// Read addresses and ports
	if header.transportProtocol.IsIPv4() {
		var addr _addr4
		if err := binary.Read(io.LimitReader(reader, int64(length)), binary.BigEndian, &addr); err != nil {
			return nil, ErrInvalidAddress
		}
		header.sourceAddress = addr.Src[:]
		header.destinationAddress = addr.Dst[:]
		header.sourcePort = addr.SrcPort
		header.destinationPort = addr.DstPort
		tlvLength = length - v2AddrLenInet
	} else if header.transportProtocol.IsIPv6() {
		var addr _addr6
		if err := binary.Read(io.LimitReader(reader, int64(length)), binary.BigEndian, &addr); err != nil {
			return nil, ErrInvalidAddress
		}
		header.sourceAddress = addr.Src[:]
		header.destinationAddress = addr.Dst[:]
		header.sourcePort = addr.SrcPort
		header.destinationPort = addr.DstPort
		tlvLength = length - v2AddrLenInet6
	}
	// TODO fully support Unix addresses
	//	else if header.transportProtocol.IsUnix() {
	//		var addr _addrUnix
	//		if err := binary.Read(io.LimitReader(reader, int64(length)), binary.BigEndian, &addr); err != nil {
	//			return nil, ErrInvalidAddress
	//		}
	//
	//if header.sourceAddress, err = net.ResolveUnixAddr("unix", string(addr.Src[:])); err != nil {
	//	return nil, ErrCantResolveSourceUnixAddress
	//}
	//if header.destinationAddress, err = net.ResolveUnixAddr("unix", string(addr.Dst[:])); err != nil {
	//	return nil, ErrCantResolveDestinationUnixAddress
	//}
	//}

	header.parseVersion2Tlv(reader, tlvLength)
	return header, nil
}

func (header *v2header) parseVersion2Tlv(reader *bufio.Reader, length uint16) error {
	for length > 0 {
		if err := header.parseV2TlvField(reader, &length); err != nil {
			return err
		}
	}
	return nil
}

func (header *v2header) parseV2TlvField(reader *bufio.Reader, length *uint16) error {
	tlvType, err := reader.ReadByte()
	if err != nil {
		return errors.New("Could not read TLV type: " + err.Error())
	}

	var tlvLength uint16
	if err := binary.Read(io.LimitReader(reader, 2), binary.BigEndian, &tlvLength); err != nil {
		return errors.New("Could not read TLV length: " + err.Error())
	}

	if tlvLength+v2TlvHeaderLen > *length {
		return fmt.Errorf("TLV Field Length is longer than total proxyprotocol length remainder (%d + 3) > %d",
			tlvLength, *length)
	}
	*length = *length - (v2TlvHeaderLen + tlvLength)

	switch tlvType {
	case v2TlvTypeAlpn:
		if header.Alpn, err = header.parseV2TlvGenericBytes(reader, tlvLength); err != nil {
			return err
		}
	case v2TlvTypeAuthority:
		if header.Authority, err = header.parseV2TlvGenericString(reader, tlvLength); err != nil {
			return err
		}
	case v2TlvTypeCrc32c:
		// Not (yet) implemented
	case v2TlvTypeNoop:
		// "The TLV of this type should be ignored when parsed."
	case v2TlvTypeSsl:
		if err = header.parseV2TlvSsl(reader, tlvLength); err != nil {
			return err
		}
	case v2TlvSubtypeSslVersion:
		if header.SslVersion, err = header.parseV2TlvGenericString(reader, tlvLength); err != nil {
			return err
		}
	case v2TlvSubtypeSslCn:
		if header.SslCn, err = header.parseV2TlvGenericString(reader, tlvLength); err != nil {
			return err
		}
	case v2TlvSubtypeSslCipher:
		if header.SslCipher, err = header.parseV2TlvGenericString(reader, tlvLength); err != nil {
			return err
		}
	case v2TlvSubtypeSslSigAlg:
		if header.SslSigAlg, err = header.parseV2TlvGenericString(reader, tlvLength); err != nil {
			return err
		}
	case v2TlvSubtypeSslKeyAlg:
		if header.SslKeyAlg, err = header.parseV2TlvGenericString(reader, tlvLength); err != nil {
			return err
		}
	case v2TlvTypeNetNs:
		if header.netNs, err = header.parseV2TlvGenericString(reader, tlvLength); err != nil {
			return err
		}
	case v2TlvTypeCustom0,
		v2TlvTypeCustom1,
		v2TlvTypeCustom2,
		v2TlvTypeCustom3,
		v2TlvTypeCustom4,
		v2TlvTypeCustom5,
		v2TlvTypeCustom6,
		v2TlvTypeCustom7,
		v2TlvTypeCustom8,
		v2TlvTypeCustom9,
		v2TlvTypeCustom10,
		v2TlvTypeCustom11,
		v2TlvTypeCustom12,
		v2TlvTypeCustom13,
		v2TlvTypeCustom14,
		v2TlvTypeCustom15:
		if header.Custom[tlvType], err = header.parseV2TlvGenericBytes(reader, tlvLength); err != nil {
			return err
		}
	case v2TlvTypeExperiment0,
		v2TlvTypeExperiment1,
		v2TlvTypeExperiment2,
		v2TlvTypeExperiment3,
		v2TlvTypeExperiment4,
		v2TlvTypeExperiment5,
		v2TlvTypeExperiment6,
		v2TlvTypeExperiment7:
		if header.Custom[tlvType], err = header.parseV2TlvGenericBytes(reader, tlvLength); err != nil {
			return err
		}
	default:
		fmt.Println("Unimplemented TLV Type:", tlvType)
	}

	return nil
}

func (header *v2header) parseV2TlvSsl(reader *bufio.Reader, maxLength uint16) error {
	if maxLength < 5 {
		return errors.New("SSL TLV length too short")
	}

	clientBits, err := reader.ReadByte()
	if err != nil {
		return errors.New("Could not read SSL Client bits: " + err.Error())
	}

	reader.Discard(4) // Verify field is not fully documented. Not implementing for now
	header.SslClientBits = clientBits
	header.SslClientSsl = clientBits&0x01 != 0
	header.SslClientCertConn = clientBits&0x02 != 0
	header.SslClientCertSess = clientBits&0x04 != 0

	// Parse SSL Subtypes
	header.parseVersion2Tlv(reader, maxLength-5)

	return nil
}

func (header *v2header) parseV2TlvGenericBytes(reader *bufio.Reader, maxLength uint16) ([]byte, error) {
	buf := make([]byte, maxLength)
	_, err := reader.Read(buf)
	if err != nil {
		return buf, err
	}
	return buf, nil
}

func (header *v2header) parseV2TlvGenericString(reader *bufio.Reader, maxLength uint16) (string, error) {
	res, err := header.parseV2TlvGenericBytes(reader, maxLength)
	return string(res), err
}

func (header *v2header) Format() ([]byte, error) {
	var buf bytes.Buffer
	buf.Write(SIGV2)
	buf.WriteByte(header.command.toByte())
	if !header.command.IsLocal() {
		buf.WriteByte(header.transportProtocol.toByte())
		// TODO add encapsulated TLV length
		var addrSrc, addrDst []byte
		if header.transportProtocol.IsIPv4() {
			buf.Write(lengthV4Bytes)
			addrSrc = header.sourceAddress.To4()
			addrDst = header.destinationAddress.To4()
		} else if header.transportProtocol.IsIPv6() {
			buf.Write(lengthV6Bytes)
			addrSrc = header.sourceAddress.To16()
			addrDst = header.destinationAddress.To16()
		} else if header.transportProtocol.IsUnix() {
			buf.Write(lengthUnixBytes)
			// TODO is below right?
			addrSrc = []byte(header.sourceAddress.String())
			addrDst = []byte(header.destinationAddress.String())
		}
		buf.Write(addrSrc)
		buf.Write(addrDst)

		portSrcBytes := func() []byte {
			a := make([]byte, 2)
			binary.BigEndian.PutUint16(a, header.sourcePort)
			return a
		}()
		buf.Write(portSrcBytes)

		portDstBytes := func() []byte {
			a := make([]byte, 2)
			binary.BigEndian.PutUint16(a, header.destinationPort)
			return a
		}()
		buf.Write(portDstBytes)

	}

	return buf.Bytes(), nil
}

func (header *v2header) validateLength(length uint16) bool {
	if header.transportProtocol.IsIPv4() {
		return length >= v2AddrLenInet
	} else if header.transportProtocol.IsIPv6() {
		return length >= v2AddrLenInet6
	} else if header.transportProtocol.IsUnix() {
		return length >= v2AddrLenUnix
	}
	// TODO: Unspec?

	return false
}
