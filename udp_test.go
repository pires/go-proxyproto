package proxyproto

import (
	"bytes"
	"errors"
	"net"
	"testing"
)

// TestParseUDPDatagram pins the spec's UDP mode (section 2): the header and
// the proxied payload share one datagram, and each datagram is parsed
// independently. Positive cases return the header and the exact payload;
// datagrams without a complete valid header are rejected, never treated as
// raw payload.
func TestParseUDPDatagram(t *testing.T) {
	payload := []byte("proxied application datagram")

	t.Run("v2 PROXY UDPv4 with payload", func(t *testing.T) {
		udpHeader := &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: UDPv4,
			SourceAddr:        &net.UDPAddr{IP: net.ParseIP("10.1.1.1"), Port: 1000},
			DestinationAddr:   &net.UDPAddr{IP: net.ParseIP("20.2.2.2"), Port: 2000},
		}
		datagram, err := udpHeader.FormatUDPDatagram(payload)
		if err != nil {
			t.Fatalf("FormatUDPDatagram failed: %v", err)
		}

		h, rest, err := ParseUDPDatagram(datagram)
		if err != nil {
			t.Fatalf("datagram was rejected: %v", err)
		}
		if !h.EqualsTo(udpHeader) {
			t.Fatalf("expected %#v, actual %#v", udpHeader, h)
		}
		if !bytes.Equal(rest, payload) {
			t.Fatalf("payload = %q, want %q", rest, payload)
		}
	})

	t.Run("v2 LOCAL UNSPEC with payload", func(t *testing.T) {
		datagram := append(v2Header(byte(LOCAL), byte(UNSPEC), nil), payload...)
		h, rest, err := ParseUDPDatagram(datagram)
		if err != nil {
			t.Fatalf("datagram was rejected: %v", err)
		}
		if !h.Command.IsLocal() {
			t.Fatalf("expected LOCAL command, got %#x", byte(h.Command))
		}
		if !bytes.Equal(rest, payload) {
			t.Fatalf("payload = %q, want %q", rest, payload)
		}
	})

	t.Run("v1 header with payload", func(t *testing.T) {
		datagram := append([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 80 443\r\n"), payload...)
		h, rest, err := ParseUDPDatagram(datagram)
		if err != nil {
			t.Fatalf("datagram was rejected: %v", err)
		}
		if h.Version != 1 {
			t.Fatalf("expected v1 header, got version %d", h.Version)
		}
		if !bytes.Equal(rest, payload) {
			t.Fatalf("payload = %q, want %q", rest, payload)
		}
	})

	t.Run("header only, empty payload", func(t *testing.T) {
		datagram := v2Header(byte(PROXY), byte(UDPv4), make([]byte, int(lengthV4)))
		h, rest, err := ParseUDPDatagram(datagram)
		if err != nil {
			t.Fatalf("datagram was rejected: %v", err)
		}
		if h == nil || len(rest) != 0 {
			t.Fatalf("expected empty payload, got %q", rest)
		}
	})

	t.Run("no header is not guessed as payload", func(t *testing.T) {
		_, _, err := ParseUDPDatagram([]byte("just application data"))
		if !errors.Is(err, ErrNoProxyProtocol) {
			t.Fatalf("expected ErrNoProxyProtocol, got %v", err)
		}
	})

	t.Run("empty datagram", func(t *testing.T) {
		if _, _, err := ParseUDPDatagram(nil); !errors.Is(err, ErrNoProxyProtocol) {
			t.Fatalf("expected ErrNoProxyProtocol, got %v", err)
		}
	})

	t.Run("truncated v2 header", func(t *testing.T) {
		// Declared address block missing entirely: the datagram carries fewer
		// bytes than the header announces, and unlike a stream no more bytes can
		// ever arrive.
		datagram := append(append(bytes.Clone(SIGV2), byte(PROXY), byte(UDPv4)), lengthV4Bytes...)
		if _, _, err := ParseUDPDatagram(datagram); err == nil {
			t.Fatal("truncated datagram must be rejected")
		}
	})
}

// TestFormatUDPDatagramError pins that a header that cannot Format surfaces
// the error instead of emitting a datagram with a bogus header.
func TestFormatUDPDatagramError(t *testing.T) {
	h := &Header{Version: 9}
	if _, err := h.FormatUDPDatagram([]byte("payload")); !errors.Is(err, ErrUnknownProxyProtocolVersion) {
		t.Fatalf("expected ErrUnknownProxyProtocolVersion, got %v", err)
	}
}

// FuzzParseUDPDatagram holds the datagram invariants under random input: an
// accepted datagram must re-serialize stably (header format + payload equals a
// datagram that parses to the same result), and the payload must never be
// invented — it is always a suffix of the input.
func FuzzParseUDPDatagram(f *testing.F) {
	f.Add(append(v2Header(byte(PROXY), byte(UDPv4), make([]byte, int(lengthV4))), []byte("payload")...))
	f.Add(append([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 80 443\r\n"), []byte("payload")...))
	f.Add(v2Header(byte(LOCAL), byte(UNSPEC), nil))
	f.Add([]byte("just application data"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		h, payload, err := ParseUDPDatagram(data)
		if err != nil {
			return
		}
		if !bytes.HasSuffix(data, payload) {
			t.Fatalf("payload %q is not a suffix of the datagram", payload)
		}
		// Round-trip: rebuilding the datagram from the parsed header must
		// yield a datagram that parses to an equal header and byte-identical
		// payload, and re-formats identically (stability).
		out, err := h.FormatUDPDatagram(payload)
		if err != nil {
			t.Fatalf("accepted header failed to FormatUDPDatagram: %v", err)
		}
		h2, payload2, err := ParseUDPDatagram(out)
		if err != nil {
			t.Fatalf("re-parse of formatted datagram failed: %v", err)
		}
		if !bytes.Equal(payload2, payload) {
			t.Fatalf("payload not preserved: %q != %q", payload2, payload)
		}
		out2, err := h2.FormatUDPDatagram(payload2)
		if err != nil || !bytes.Equal(out, out2) {
			t.Fatalf("datagram format not stable: %v\n first  %x\n second %x", err, out, out2)
		}
	})
}
