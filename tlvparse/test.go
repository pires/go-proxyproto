package tlvparse

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/pires/go-proxyproto"
)

func checkTLVs(t *testing.T, name string, raw []byte, expected []proxyproto.PP2Type) []proxyproto.TLV {
	header, err := proxyproto.Read(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("%s: Unexpected error reading header %#v", name, err)
	}

	tlvs, err := header.TLVs()
	if err != nil {
		t.Fatalf("%s: Unexpected error splitting TLVS %#v", name, err)
	}

	if len(tlvs) != len(expected) {
		t.Fatalf("%s: Expected %d TLVs, actual %d", name, len(expected), len(tlvs))
	}

	for i, et := range expected {
		if at := tlvs[i].Type; at != et {
			t.Fatalf("%s: Expected type %X, actual %X", name, et, at)
		}
	}

	return tlvs
}
