package proxyproto

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

var (
	IPv4AddressesAndPorts        = strings.Join([]string{IP4_ADDR, IP4_ADDR, strconv.Itoa(PORT), strconv.Itoa(PORT)}, separator)
	IPv4AddressesAndInvalidPorts = strings.Join([]string{IP4_ADDR, IP4_ADDR, strconv.Itoa(INVALID_PORT), strconv.Itoa(INVALID_PORT)}, separator)
	IPv6AddressesAndPorts        = strings.Join([]string{IP6_ADDR, IP6_ADDR, strconv.Itoa(PORT), strconv.Itoa(PORT)}, separator)
	IPv6LongAddressesAndPorts    = strings.Join([]string{IP6_LONG_ADDR, IP6_LONG_ADDR, strconv.Itoa(PORT), strconv.Itoa(PORT)}, separator)

	fixtureTCP4V1 = "PROXY TCP4 " + IPv4AddressesAndPorts + crlf + "GET /"
	fixtureTCP6V1 = "PROXY TCP6 " + IPv6AddressesAndPorts + crlf + "GET /"

	fixtureTCP6V1Overflow = "PROXY TCP6 " + IPv6LongAddressesAndPorts

	fixtureUnknown              = "PROXY UNKNOWN" + crlf
	fixtureUnknownWithAddresses = "PROXY UNKNOWN " + IPv4AddressesAndInvalidPorts + crlf
)

var invalidParseV1Tests = []struct {
	desc          string
	reader        *bufio.Reader
	expectedError error
}{
	{
		desc:          "no signature",
		reader:        newBufioReader([]byte(NO_PROTOCOL)),
		expectedError: ErrNoProxyProtocol,
	},
	{
		desc:          "prox",
		reader:        newBufioReader([]byte("PROX")),
		expectedError: ErrNoProxyProtocol,
	},
	{
		desc:          "proxy lf",
		reader:        newBufioReader([]byte("PROXY \n")),
		expectedError: ErrLineMustEndWithCrlf,
	},
	{
		desc:          "proxy crlf",
		reader:        newBufioReader([]byte("PROXY " + crlf)),
		expectedError: ErrCantReadAddressFamilyAndProtocol,
	},
	{
		desc:          "proxy no space crlf",
		reader:        newBufioReader([]byte("PROXY" + crlf)),
		expectedError: ErrCantReadAddressFamilyAndProtocol,
	},
	{
		desc:          "proxy something crlf",
		reader:        newBufioReader([]byte("PROXY SOMETHING" + crlf)),
		expectedError: ErrCantReadAddressFamilyAndProtocol,
	},
	{
		desc:          "incomplete signature TCP4",
		reader:        newBufioReader([]byte("PROXY TCP4 " + IPv4AddressesAndPorts)),
		expectedError: ErrCantReadVersion1Header,
	},
	{
		desc:          "TCP6 with IPv4 addresses",
		reader:        newBufioReader([]byte("PROXY TCP6 " + IPv4AddressesAndPorts + crlf)),
		expectedError: ErrInvalidAddress,
	},
	{
		desc:          "TCP4 with IPv6 addresses",
		reader:        newBufioReader([]byte("PROXY TCP4 " + IPv6AddressesAndPorts + crlf)),
		expectedError: ErrInvalidAddress,
	},
	{
		desc:          "TCP4 with invalid port",
		reader:        newBufioReader([]byte("PROXY TCP4 " + IPv4AddressesAndInvalidPorts + crlf)),
		expectedError: ErrInvalidPortNumber,
	},
	{
		desc:          "header too long",
		reader:        newBufioReader([]byte("PROXY UNKNOWN " + IPv6LongAddressesAndPorts + " " + crlf)),
		expectedError: ErrVersion1HeaderTooLong,
	},
}

func TestReadV1Invalid(t *testing.T) {
	for _, tt := range invalidParseV1Tests {
		t.Run(tt.desc, func(t *testing.T) {
			if _, err := Read(tt.reader); err != tt.expectedError {
				t.Fatalf("expected %s, actual %v", tt.expectedError, err)
			}
		})
	}
}

var validParseAndWriteV1Tests = []struct {
	desc           string
	reader         *bufio.Reader
	expectedHeader *Header
}{
	{
		desc:   "TCP4",
		reader: bufio.NewReader(strings.NewReader(fixtureTCP4V1)),
		expectedHeader: &Header{
			Version:           1,
			Command:           PROXY,
			TransportProtocol: TCPv4,
			SourceAddr:        v4addr,
			DestinationAddr:   v4addr,
		},
	},
	{
		desc:   "TCP6",
		reader: bufio.NewReader(strings.NewReader(fixtureTCP6V1)),
		expectedHeader: &Header{
			Version:           1,
			Command:           PROXY,
			TransportProtocol: TCPv6,
			SourceAddr:        v6addr,
			DestinationAddr:   v6addr,
		},
	},
	{
		desc:   "unknown",
		reader: bufio.NewReader(strings.NewReader(fixtureUnknown)),
		expectedHeader: &Header{
			Version:           1,
			Command:           LOCAL,
			TransportProtocol: UNSPEC,
			SourceAddr:        nil,
			DestinationAddr:   nil,
		},
	},
	{
		desc:   "unknown with addresses and ports",
		reader: bufio.NewReader(strings.NewReader(fixtureUnknownWithAddresses)),
		expectedHeader: &Header{
			Version:           1,
			Command:           LOCAL,
			TransportProtocol: UNSPEC,
			SourceAddr:        nil,
			DestinationAddr:   nil,
		},
	},
}

func TestParseV1Valid(t *testing.T) {
	for _, tt := range validParseAndWriteV1Tests {
		t.Run(tt.desc, func(t *testing.T) {
			header, err := Read(tt.reader)
			if err != nil {
				t.Fatal("unexpected error", err.Error())
			}
			if !header.EqualsTo(tt.expectedHeader) {
				t.Fatalf("expected %#v, actual %#v", tt.expectedHeader, header)
			}
		})
	}
}

func TestWriteV1Valid(t *testing.T) {
	for _, tt := range validParseAndWriteV1Tests {
		t.Run(tt.desc, func(t *testing.T) {
			var b bytes.Buffer
			w := bufio.NewWriter(&b)
			if _, err := tt.expectedHeader.WriteTo(w); err != nil {
				t.Fatal("unexpected error ", err)
			}
			w.Flush()

			// Read written bytes to validate written header
			r := bufio.NewReader(&b)
			newHeader, err := Read(r)
			if err != nil {
				t.Fatal("unexpected error ", err)
			}

			if !newHeader.EqualsTo(tt.expectedHeader) {
				t.Fatalf("expected %#v, actual %#v", tt.expectedHeader, newHeader)
			}
		})
	}
}

// Tests for parseVersion1 overflow - issue #69.

type dataSource struct {
	NBytes int
	NRead  int
}

func (ds *dataSource) Read(b []byte) (int, error) {
	if ds.NRead >= ds.NBytes {
		return 0, io.EOF
	}
	avail := ds.NBytes - ds.NRead
	if len(b) < avail {
		avail = len(b)
	}
	for i := 0; i < avail; i++ {
		b[i] = 0x20
	}
	ds.NRead += avail
	return avail, nil
}

func TestParseVersion1Overflow(t *testing.T) {
	ds := &dataSource{}
	reader := bufio.NewReader(ds)
	bufSize := reader.Size()
	ds.NBytes = bufSize * 16
	parseVersion1(reader)
	if ds.NRead > bufSize {
		t.Fatalf("read: expected max %d bytes, actual %d\n", bufSize, ds.NRead)
	}
}

func listen(t *testing.T) *Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return &Listener{Listener: l}
}

func client(t *testing.T, addr, header string, length int, terminate bool, wait time.Duration, done chan struct{}) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	if terminate && length < 2 {
		length = 2
	}

	buf := make([]byte, len(header)+length)
	copy(buf, []byte(header))
	for i := 0; i < length-2; i++ {
		buf[i+len(header)] = 0x20
	}
	if terminate {
		copy(buf[len(header)+length-2:], []byte(crlf))
	}

	n, err := c.Write(buf)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(buf) {
		t.Fatalf("write; short write")
	}

	time.Sleep(wait)
	close(done)
}

func TestVersion1Overflow(t *testing.T) {
	done := make(chan struct{})

	l := listen(t)
	go client(t, l.Addr().String(), fixtureTCP6V1Overflow, 10240, true, 10*time.Second, done)

	c, err := l.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	b := []byte{}
	_, err = c.Read(b)
	if err == nil {
		t.Fatalf("net.Conn: no error reported for oversized header")
	}
}

func TestVersion1SlowLoris(t *testing.T) {
	done := make(chan struct{})
	timeout := make(chan error)

	l := listen(t)
	go client(t, l.Addr().String(), fixtureTCP6V1Overflow, 0, false, 10*time.Second, done)

	c, err := l.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	go func() {
		b := []byte{}
		_, err = c.Read(b)
		timeout <- err
	}()

	select {
	case <-done:
		t.Fatalf("net.Conn: reader still blocked after 10 seconds")
	case err := <-timeout:
		if err == nil {
			t.Fatalf("net.Conn: no error reported for incomplete header")
		}
	}
}

func TestVersion1SlowLorisOverflow(t *testing.T) {
	done := make(chan struct{})
	timeout := make(chan error)

	l := listen(t)
	go client(t, l.Addr().String(), fixtureTCP6V1Overflow, 10240, false, 10*time.Second, done)

	c, err := l.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	go func() {
		b := []byte{}
		_, err = c.Read(b)
		timeout <- err
	}()

	select {
	case <-done:
		t.Fatalf("net.Conn: reader still blocked after 10 seconds")
	case err := <-timeout:
		if err == nil {
			t.Fatalf("net.Conn: no error reported for incomplete and overflowed header")
		}
	}
}
