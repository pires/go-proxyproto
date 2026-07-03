package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"reflect"
	"testing"
)

// mustNotPanicAddr exercises a net.Addr exactly like a typical application would
// (logging, allow-listing, metrics). A nil address stored in a header would
// panic here, which is the failure mode the transport-protocol whitelist and the
// RemoteAddr/LocalAddr nil guards exist to prevent.
func mustNotPanicAddr(t *testing.T, a net.Addr) {
	t.Helper()
	if a == nil {
		return
	}
	_ = a.String()
	_ = a.Network()
}

func v2Header(command, transport byte, payload []byte) []byte {
	var b bytes.Buffer
	b.Write(SIGV2)
	b.WriteByte(command)
	b.WriteByte(transport)
	l := make([]byte, 2)
	//nolint:gosec // test payloads are well under 64KiB.
	binary.BigEndian.PutUint16(l, uint16(len(payload)))
	b.Write(l)
	b.Write(payload)
	return b.Bytes()
}

// TestV2UndefinedTransportRejected pins spec section 2.2: every
// family/transport byte outside the defined combinations "must be rejected as
// invalid by receivers", under PROXY and LOCAL commands alike. For PROXY this
// is also the guard against the nil-address regression: a byte with a known
// family but an undefined transport (e.g. 0x13) would otherwise be parsed into
// a header with nil addresses that panics callers of RemoteAddr().String().
func TestV2UndefinedTransportRejected(t *testing.T) {
	for b := range 256 {
		if supportedTransportProtocol[AddressFamilyAndProtocol(b)] {
			continue // defined combinations are covered by the valid-parse tests
		}
		// Provide a generous, spec-min-satisfying payload so the only reason to
		// reject is the transport byte itself.
		payload := make([]byte, int(lengthUnix))
		for _, cmd := range []ProtocolVersionAndCommand{PROXY, LOCAL} {
			raw := v2Header(byte(cmd), byte(b), payload)
			h, err := Read(bufio.NewReader(bytes.NewReader(raw)))
			if !errors.Is(err, ErrUnsupportedAddressFamilyAndProtocol) {
				t.Fatalf("command %#x transport %#x: expected ErrUnsupportedAddressFamilyAndProtocol, got err=%v header=%+v",
					byte(cmd), b, err, h)
			}
		}
	}
}

// TestParseV2LocalAddressBlock pins spec-conformant LOCAL handling (section
// 2.2). The receiver must use the real connection endpoints for LOCAL, must
// skip exactly `length` payload bytes, and "must not assume zero is presented
// for LOCAL connections". Two shapes follow from that:
//
//   - A LOCAL frame whose length fits its declared family layout is decoded
//     like a PROXY frame: informational addresses and trailing TLVs are
//     preserved, so the header can round-trip through Format/WriteTo.
//   - A LOCAL frame whose length does not fit the family layout (e.g.
//     LOCAL + TCPv4 + len 0) is still valid; its payload is skipped and the
//     header is normalized to UNSPEC so it remains serializable.
//
// Either way Conn.RemoteAddr/LocalAddr fall back to the real endpoints via
// IsLocal, and every accepted header must Format without error.
func TestParseV2LocalAddressBlock(t *testing.T) {
	localTLV := []byte{0x01, 0x00, 0x01, 0xAA}
	fullV4Block := make([]byte, int(lengthV4))
	shortBlock := append(bytes.Clone(localTLV), make([]byte, int(lengthV4)-len(localTLV)-1)...) // 11 bytes: < TCPv4 layout

	cases := []struct {
		desc          string
		transport     byte
		payload       []byte
		wantTransport AddressFamilyAndProtocol
		wantAddrs     bool
		wantRawTLVs   []byte
	}{
		{"UNSPEC, empty", byte(UNSPEC), nil, UNSPEC, false, nil},
		{"UNSPEC, TLV payload preserved", byte(UNSPEC), localTLV, UNSPEC, false, localTLV},
		{"TCPv4 with a full address block decoded", byte(TCPv4), fullV4Block, TCPv4, true, nil},
		{"UDPv4 with a full address block decoded", byte(UDPv4), fullV4Block, UDPv4, true, nil},
		{"TCPv4 with address block and TLVs preserved", byte(TCPv4), append(bytes.Clone(fullV4Block), localTLV...), TCPv4, true, localTLV},
		{"TCPv4 with len 0 normalized to UNSPEC", byte(TCPv4), nil, UNSPEC, false, nil},
		{"TCPv4 with short block skipped and normalized", byte(TCPv4), shortBlock, UNSPEC, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			raw := v2Header(byte(LOCAL), tc.transport, tc.payload)
			h, err := Read(bufio.NewReader(bytes.NewReader(raw)))
			if err != nil {
				t.Fatalf("LOCAL frame was rejected: %v", err)
			}
			if !h.Command.IsLocal() {
				t.Fatalf("expected LOCAL command, got %#x", byte(h.Command))
			}
			if h.TransportProtocol != tc.wantTransport {
				t.Fatalf("TransportProtocol = %#x, want %#x", byte(h.TransportProtocol), byte(tc.wantTransport))
			}
			if gotAddrs := h.SourceAddr != nil && h.DestinationAddr != nil; gotAddrs != tc.wantAddrs {
				t.Fatalf("addresses decoded = %v, want %v (src=%v dst=%v)", gotAddrs, tc.wantAddrs, h.SourceAddr, h.DestinationAddr)
			}
			if !bytes.Equal(h.rawTLVs, tc.wantRawTLVs) {
				t.Fatalf("rawTLVs = %x, want %x", h.rawTLVs, tc.wantRawTLVs)
			}
			mustNotPanicAddr(t, h.SourceAddr)
			mustNotPanicAddr(t, h.DestinationAddr)
			// Every accepted LOCAL header must be serializable again, whether
			// decoded or normalized.
			if _, err := h.Format(); err != nil {
				t.Fatalf("accepted LOCAL header failed to Format: %v", err)
			}
		})
	}
}

// TestParseV2RoundTrip pins byte-for-byte round-tripping — the relay use case
// (Read then WriteTo toward a backend) — for frames carrying a full family
// address block plus TLVs. The Unix cases guard the declared-length accounting:
// formatVersion2 used to write the fixed 216-byte Unix length while appending
// TLVs after the block, leaving a downstream parser to read the TLV bytes as
// application payload.
func TestParseV2RoundTrip(t *testing.T) {
	tlv := []byte{0x01, 0x00, 0x01, 0xAA}
	v4Block := []byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 80, 1, 187}
	unixBlock := make([]byte, int(lengthUnix))
	copy(unixBlock, "/tmp/src.sock")
	copy(unixBlock[int(lengthUnix)/2:], "/tmp/dst.sock")

	cases := []struct {
		desc      string
		command   ProtocolVersionAndCommand
		transport AddressFamilyAndProtocol
		block     []byte
	}{
		{"LOCAL TCPv4 with TLV", LOCAL, TCPv4, v4Block},
		{"LOCAL UnixStream with TLV", LOCAL, UnixStream, unixBlock},
		{"PROXY UnixStream with TLV", PROXY, UnixStream, unixBlock},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			raw := v2Header(byte(tc.command), byte(tc.transport), append(bytes.Clone(tc.block), tlv...))
			h, err := Read(bufio.NewReader(bytes.NewReader(raw)))
			if err != nil {
				t.Fatalf("frame was rejected: %v", err)
			}
			got, err := h.Format()
			if err != nil {
				t.Fatalf("Format failed: %v", err)
			}
			if !bytes.Equal(got, raw) {
				t.Fatalf("round-trip mismatch:\n got  %x\n want %x", got, raw)
			}
		})
	}
}

// TestParsedHeaderNeverHasNilProxyAddr is the invariant that guards the bug
// class directly: a successfully parsed PROXY (non-LOCAL, non-UNSPEC) header
// must carry usable source and destination addresses.
func TestParsedHeaderNeverHasNilProxyAddr(t *testing.T) {
	check := func(raw []byte) {
		h, err := Read(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil || h == nil {
			return
		}
		if h.Command.IsProxy() && h.TransportProtocol != UNSPEC {
			if h.SourceAddr == nil || h.DestinationAddr == nil {
				t.Fatalf("parsed PROXY header has nil addr: src=%v dst=%v transport=%#x",
					h.SourceAddr, h.DestinationAddr, byte(h.TransportProtocol))
			}
		}
		mustNotPanicAddr(t, h.SourceAddr)
		mustNotPanicAddr(t, h.DestinationAddr)
	}
	for b := range 256 {
		check(v2Header(byte(PROXY), byte(b), make([]byte, int(lengthUnix))))
		check(v2Header(byte(LOCAL), byte(b), make([]byte, int(lengthUnix))))
	}
}

// TestRemoteAddrNoPanicOnCraftedTransport pins the original public failure mode
// end to end: a client sending a v2 header with an undefined transport byte
// (0x13) over a real Conn must not be able to make RemoteAddr()/LocalAddr()
// panic. The header is now rejected by the parser, so the accessors fall back to
// the underlying connection's addresses.
func TestRemoteAddrNoPanicOnCraftedTransport(t *testing.T) {
	conn, peer := net.Pipe()
	defer func() { _ = conn.Close() }()

	raw := v2Header(byte(PROXY), 0x13, make([]byte, int(lengthV4)))
	go func() {
		_, _ = peer.Write(raw)
		_ = peer.Close()
	}()

	c := NewConn(conn)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("addr accessor panicked on crafted header: %v", r)
		}
	}()
	if got := c.RemoteAddr(); got == nil || got.String() == "" {
		t.Fatalf("RemoteAddr returned unusable addr: %v", got)
	}
	if got := c.LocalAddr(); got == nil || got.String() == "" {
		t.Fatalf("LocalAddr returned unusable addr: %v", got)
	}
}

// TestAddrAccessorsNilGuard pins the defense-in-depth guards in RemoteAddr and
// LocalAddr: even if a processed header somehow carries nil proxy addresses
// (e.g. a hand-built Header or a future code path), the accessors must fall back
// to the underlying connection instead of panicking.
func TestAddrAccessorsNilGuard(t *testing.T) {
	conn, peer := net.Pipe()
	defer func() { _ = conn.Close() }()
	defer func() { _ = peer.Close() }()

	c := NewConn(conn)
	// A PROXY, non-UNSPEC header with nil addresses. Consume the sync.Once so
	// ensureHeaderProcessed does not try to read a header off the pipe.
	c.header = &Header{Version: 2, Command: PROXY, TransportProtocol: TCPv4}
	c.once.Do(func() {})

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("addr accessor panicked on nil header addr: %v", r)
		}
	}()
	if got := c.RemoteAddr(); got != conn.RemoteAddr() {
		t.Errorf("RemoteAddr = %v, want underlying %v", got, conn.RemoteAddr())
	}
	if got := c.LocalAddr(); got != conn.LocalAddr() {
		t.Errorf("LocalAddr = %v, want underlying %v", got, conn.LocalAddr())
	}
}

func FuzzRead(f *testing.F) {
	// Seeds: a valid v1 line, valid v2 TCPv4, and the crafted transport byte.
	f.Add([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 80 443\r\n"))
	f.Add([]byte("PROXY UNKNOWN\r\n"))
	f.Add(v2Header(byte(PROXY), byte(TCPv4), make([]byte, int(lengthV4))))
	f.Add(v2Header(byte(PROXY), byte(TCPv6), make([]byte, int(lengthV6))))
	f.Add(v2Header(byte(LOCAL), byte(UNSPEC), nil))
	f.Add(v2Header(byte(LOCAL), byte(TCPv4), nil))
	f.Add(v2Header(byte(LOCAL), byte(TCPv4), make([]byte, int(lengthV4))))
	f.Add(v2Header(byte(PROXY), 0x13, make([]byte, int(lengthV4))))
	f.Add([]byte("PROXYjunk TCP4 1.2.3.4 5.6.7.8 80 443\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := Read(bufio.NewReader(bytes.NewReader(data)))
		if err != nil || h == nil {
			return
		}
		// A parsed PROXY header must never expose nil proxy addresses.
		if h.Command.IsProxy() && h.TransportProtocol != UNSPEC {
			if h.SourceAddr == nil || h.DestinationAddr == nil {
				t.Fatalf("parsed PROXY header has nil addr: %+v", h)
			}
		}
		mustNotPanicAddr(t, h.SourceAddr)
		mustNotPanicAddr(t, h.DestinationAddr)
		// TLV access must not panic on any accepted header.
		_, _ = h.TLVs()
		// Any header accepted off the wire must be serializable again: Read and
		// Format/WriteTo act as a round-trip pair for relays, so an accepted
		// header that cannot Format is a parser bug.
		out, err := h.Format()
		if err != nil {
			t.Fatalf("accepted header failed to Format: %v (header %+v)", err, h)
		}
		// And the formatted bytes must be a valid, stable header themselves:
		// re-reading and re-formatting must reproduce them exactly. This catches
		// declared-length accounting bugs (e.g. TLV bytes emitted after the
		// declared header length) that a Format-succeeds check alone misses.
		h2, err := Read(bufio.NewReader(bytes.NewReader(out)))
		if err != nil {
			t.Fatalf("re-parse of formatted header failed: %v (bytes %x)", err, out)
		}
		out2, err := h2.Format()
		if err != nil {
			t.Fatalf("re-format of formatted header failed: %v", err)
		}
		if !bytes.Equal(out, out2) {
			t.Fatalf("format not stable:\n first  %x\n second %x", out, out2)
		}
	})
}

func FuzzSplitTLVs(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x01, 0x00, 0x01, 0xAA})          // one 1-byte TLV
	f.Add([]byte{0x04, 0x00, 0x00})                // NOOP, empty
	f.Add([]byte{0x04, 0x00, 0x02, 0xDE, 0xAD})    // NOOP with payload (value is dropped on split)
	f.Add([]byte{0x20, 0x00, 0x05, 1, 0, 0, 0, 0}) // SSL-shaped
	f.Add([]byte{0x01, 0xFF, 0xFF, 0x00})          // length overruns buffer

	f.Fuzz(func(t *testing.T, data []byte) {
		tlvs, err := SplitTLVs(data)
		if err != nil {
			return
		}
		// Round-trip: joining the split TLVs must re-split to an identical
		// vector. SplitTLVs already canonicalizes (NOOP values are dropped), so
		// tlvs is the canonical form and a second split must reproduce it exactly.
		raw, err := JoinTLVs(tlvs)
		if err != nil {
			return
		}
		got, err := SplitTLVs(raw)
		if err != nil {
			t.Fatalf("re-split of joined TLVs failed: %v", err)
		}
		if !reflect.DeepEqual(got, tlvs) {
			t.Fatalf("round-trip TLV mismatch:\n got  %+v\n want %+v", got, tlvs)
		}
	})
}
