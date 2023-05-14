package resolve

import (
	"bytes"
	"net"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestHeader_MarshalBinary(t *testing.T) {
	var (
		in   = Header{ID: 0x1314, NumQuestions: 1}
		want = []byte("\x13\x14\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00")
	)

	got, err := in.MarshalBinary()
	if err != nil {
		t.Errorf("error: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestHeader_UnmarshalBinary(t *testing.T) {
	var (
		in   = []byte("`V\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00R\x9b\x00\x04]\xb8\xd8\"")
		want = Header{ID: 24662, Flags: 33152, NumQuestions: 1, NumAnswers: 1}
	)

	var got Header
	if err := got.UnmarshalBinary(in); err != nil {
		t.Errorf("error: %v", err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("(-want, +got):\n%s", diff)
	}
}

func TestDecodePacket(t *testing.T) {
	var (
		in   = []byte("`V\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00R\x9b\x00\x04]\xb8\xd8\"")
		want = &Packet{
			Header: Header{
				ID:           24662,
				Flags:        33152,
				NumQuestions: 1,
				NumAnswers:   1,
			},
			Questions: []Question{{
				Name:  []byte("www.example.com"),
				Type:  TypeA,
				Class: ClassIN,
			}},
			Answers: []Record{{
				Name:  []byte("www.example.com"),
				Type:  TypeA,
				Class: ClassIN,
				TTL:   21147,
				Data:  []byte("]\xb8\xd8\""),
			}},
		}
	)

	got, err := DecodePacket(bytes.NewReader(in))
	if err != nil {
		t.Errorf("error: %v", err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("DecodePacket mismatch (-want, +got):\n%s", diff)
	}
}

func TestEncodeDNSName(t *testing.T) {
	var (
		in   = "google.com"
		want = []byte("\x06google\x03com\x00")
	)

	got := EncodeDNSName(in)
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGoogleDNS(t *testing.T) {
	t.Skip("makes network calls")

	query, err := NewQuery("www.example.com", 1)
	if err != nil {
		t.Fatalf("NewQuery: %v", err)
	}
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	_, err = conn.Write(query)
	if err != nil {
		t.Errorf("failed write: %v", err)
	}

	// sudo tcpdump -ni any port 53
}

/*
lookup_domain("example.com")
'93.184.216.34'
lookup_domain("recurse.com")
'108.156.172.48'
lookup_domain("metafilter.com")
'54.203.56.158'
*/

func toAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestLookupDomain(t *testing.T) {
	t.Skip("makes network calls")

	// No guarantee these are consistent.
	cases := []struct {
		in   string
		want netip.Addr
	}{
		{"example.com", toAddr(t, "93.184.216.34")},
		{"recurse.com", toAddr(t, "18.164.174.83")},
		{"metafilter.com", toAddr(t, "54.203.56.158")},
	}

	for _, tc := range cases {
		got, err := LookupDomain(tc.in)
		if err != nil {
			t.Errorf("%s: error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.in, got, tc.want)
		}
	}
}

func FuzzDecodeName(f *testing.F) {
	// DecodeName calls DecodeCompressedName and vice versa, so ensure no panic
	// or hang can occur.
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecodeName(bytes.NewReader(b))
	})
}
