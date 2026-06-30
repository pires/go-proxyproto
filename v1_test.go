package proxyproto

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

var (
	IPv4AddressesAndPorts        = strings.Join([]string{testLocalhostIP4Addr, testLocalhostIP4Addr, strconv.Itoa(testValidPort), strconv.Itoa(testValidPort)}, separator)
	IPv4In6AddressesAndPorts     = strings.Join([]string{testLocalhostIP4In6Addr, testLocalhostIP4In6Addr, strconv.Itoa(testValidPort), strconv.Itoa(testValidPort)}, separator)
	IPv4AddressesAndInvalidPorts = strings.Join([]string{testLocalhostIP4Addr, testLocalhostIP4Addr, strconv.Itoa(testInvalidPort), strconv.Itoa(testInvalidPort)}, separator)
	IPv6AddressesAndPorts        = strings.Join([]string{testLocalhostIP6Addr, testLocalhostIP6Addr, strconv.Itoa(testValidPort), strconv.Itoa(testValidPort)}, separator)
	IPv6LongAddressesAndPorts    = strings.Join([]string{testIP6LongAddr, testIP6LongAddr, strconv.Itoa(testValidPort), strconv.Itoa(testValidPort)}, separator)

	fixtureTCP4V1    = "PROXY TCP4 " + IPv4AddressesAndPorts + crlf + "GET /"
	fixtureTCP6V1    = "PROXY TCP6 " + IPv6AddressesAndPorts + crlf + "GET /"
	fixtureTCP4IN6V1 = "PROXY TCP6 " + IPv4In6AddressesAndPorts + crlf + "GET /"

	fixtureTCP6V1Overflow = "PROXY TCP6 " + IPv6LongAddressesAndPorts

	fixtureUnknown              = "PROXY UNKNOWN" + crlf
	fixtureUnknownWithAddresses = "PROXY UNKNOWN " + IPv4AddressesAndInvalidPorts + crlf

	fixtureTCP6IPv4SrcIPv4Dst = "PROXY TCP6 192.0.2.1 192.0.2.2 1234 5678" + crlf
	fixtureTCP6IPv6SrcIPv4Dst = "PROXY TCP6 2001:db8::1 192.0.2.1 51512 22" + crlf
	fixtureTCP6IPv4SrcIPv6Dst = "PROXY TCP6 192.0.2.1 2001:db8::1 51512 22" + crlf
)

var invalidParseV1Tests = []struct {
	desc          string
	reader        *bufio.Reader
	expectedError error
}{
	{
		desc:          "no signature",
		reader:        newBufioReader([]byte(testNoProtocol)),
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
		desc:          "invalid IP address",
		reader:        newBufioReader([]byte("PROXY TCP4 invalid invalid 65533 65533" + crlf)),
		expectedError: ErrInvalidAddress,
	},
	{
		desc:          "TCP4 with IPv6 addresses",
		reader:        newBufioReader([]byte("PROXY TCP4 " + IPv6AddressesAndPorts + crlf)),
		expectedError: ErrInvalidAddress,
	},
	{
		desc:          "TCP4 with IPv4 mapped addresses",
		reader:        newBufioReader([]byte("PROXY TCP4 " + IPv4In6AddressesAndPorts + crlf)),
		expectedError: ErrInvalidAddress,
	},
	{
		desc:          "TCP6 with invalid address",
		reader:        newBufioReader([]byte("PROXY TCP6 not-an-ip ::1 1234 5678" + crlf)),
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
			if _, err := Read(tt.reader); !errors.Is(err, tt.expectedError) {
				t.Fatalf("expected %s, actual %v", tt.expectedError, err)
			}
		})
	}
}

var validParseAndWriteV1Tests = []struct {
	desc           string
	reader         *bufio.Reader
	expectedHeader *Header
	// expectedWrite is the exact wire output formatVersion1 must produce for
	// expectedHeader. It is asserted byte-for-byte by TestWriteV1Valid, which a
	// round-trip + EqualsTo check cannot do: EqualsTo compares net.IP.String(),
	// so a v4-mapped IPv6 ("::ffff:1.2.3.4") and its collapsed v4 form ("1.2.3.4")
	// look equal there, hiding serialization regressions.
	expectedWrite string
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
		expectedWrite: "PROXY TCP4 127.0.0.1 127.0.0.1 65533 65533" + crlf,
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
		expectedWrite: "PROXY TCP6 ::1 ::1 65533 65533" + crlf,
	},
	{
		desc:   "TCP4IN6",
		reader: bufio.NewReader(strings.NewReader(fixtureTCP4IN6V1)),
		expectedHeader: &Header{
			Version:           1,
			Command:           PROXY,
			TransportProtocol: TCPv6,
			SourceAddr:        v4addr,
			DestinationAddr:   v4addr,
		},
		// Regression lock for the netip.Addr fix: a v4 IP carried in a TCP6 header
		// must serialize as ::ffff:127.0.0.1, not the collapsed 127.0.0.1 that
		// net.IP.String() used to emit (which produced an invalid v4-in-TCP6 line).
		expectedWrite: "PROXY TCP6 ::ffff:127.0.0.1 ::ffff:127.0.0.1 65533 65533" + crlf,
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
		expectedWrite: "PROXY UNKNOWN" + crlf,
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
		// UNSPEC always serializes to the short form; addresses are dropped.
		expectedWrite: "PROXY UNKNOWN" + crlf,
	},
	{
		desc:   "TCP6 IPv4 src IPv4 dst",
		reader: bufio.NewReader(strings.NewReader(fixtureTCP6IPv4SrcIPv4Dst)),
		expectedHeader: &Header{
			Version:           1,
			Command:           PROXY,
			TransportProtocol: TCPv6,
			SourceAddr:        &net.TCPAddr{IP: net.ParseIP("192.0.2.1").To16(), Port: 1234},
			DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("192.0.2.2").To16(), Port: 5678},
		},
		// Both addresses are v4-mapped, so both must serialize in ::ffff: form.
		expectedWrite: "PROXY TCP6 ::ffff:192.0.2.1 ::ffff:192.0.2.2 1234 5678" + crlf,
	},
	{
		desc:   "TCP6 IPv6 src IPv4 dst",
		reader: bufio.NewReader(strings.NewReader(fixtureTCP6IPv6SrcIPv4Dst)),
		expectedHeader: &Header{
			Version:           1,
			Command:           PROXY,
			TransportProtocol: TCPv6,
			SourceAddr:        &net.TCPAddr{IP: net.ParseIP("2001:db8::1").To16(), Port: 51512},
			DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("192.0.2.1").To16(), Port: 22},
		},
		// Mixed family: genuine IPv6 source stays as-is, v4 dest becomes v4-mapped.
		expectedWrite: "PROXY TCP6 2001:db8::1 ::ffff:192.0.2.1 51512 22" + crlf,
	},
	{
		desc:   "TCP6 IPv4 src IPv6 dst",
		reader: bufio.NewReader(strings.NewReader(fixtureTCP6IPv4SrcIPv6Dst)),
		expectedHeader: &Header{
			Version:           1,
			Command:           PROXY,
			TransportProtocol: TCPv6,
			SourceAddr:        &net.TCPAddr{IP: net.ParseIP("192.0.2.1").To16(), Port: 51512},
			DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("2001:db8::1").To16(), Port: 22},
		},
		// Mixed family: v4 source becomes v4-mapped, genuine IPv6 dest stays as-is.
		expectedWrite: "PROXY TCP6 ::ffff:192.0.2.1 2001:db8::1 51512 22" + crlf,
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
			if err := w.Flush(); err != nil {
				t.Fatal("unexpected error ", err)
			}

			// Assert the exact wire bytes. This is what pins address-family
			// formatting (e.g. v4-mapped IPv6 rendering as ::ffff:x.x.x.x); the
			// EqualsTo round-trip below is blind to it because it compares
			// net.IP.String(), which collapses ::ffff:x.x.x.x back to x.x.x.x.
			if got := b.String(); got != tt.expectedWrite {
				t.Fatalf("expected wire %q, actual %q", tt.expectedWrite, got)
			}

			// Round-trip the written bytes to ensure the parser accepts what the
			// formatter emits (catches format/parse drift that a byte check alone
			// would miss).
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
	avail = min(avail, len(b))
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
	_, _ = parseVersion1(reader)
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

func client(t *testing.T, addr, header string, length int, terminate bool, wait time.Duration, done chan struct{},
	result chan error,
) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		result <- fmt.Errorf("dial: %w", err)
		return
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("failed to close connection: %v", err)
		}
	})

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
		result <- fmt.Errorf("write: %w", err)
		return
	}
	if n != len(buf) {
		result <- errors.New("write; short write")
		return
	}

	close(result)
	time.Sleep(wait)
	close(done)
}

func TestVersion1Overflow(t *testing.T) {
	done := make(chan struct{})
	cliResult := make(chan error)

	l := listen(t)
	go client(t, l.Addr().String(), fixtureTCP6V1Overflow, 10240, true, 10*time.Second, done, cliResult)

	c, err := l.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	b := []byte{}
	_, err = c.Read(b)
	if err == nil {
		t.Fatalf("net.Conn: no error reported for oversized header")
	}
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

func TestVersion1SlowLoris(t *testing.T) {
	done := make(chan struct{})
	cliResult := make(chan error)
	timeout := make(chan error)

	l := listen(t)
	go client(t, l.Addr().String(), fixtureTCP6V1Overflow, 0, false, 10*time.Second, done, cliResult)

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
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

func TestVersion1SlowLorisOverflow(t *testing.T) {
	done := make(chan struct{})
	cliResult := make(chan error)
	timeout := make(chan error)

	l := listen(t)
	go client(t, l.Addr().String(), fixtureTCP6V1Overflow, 10240, false, 10*time.Second, done, cliResult)

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
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}
