package resolve

import (
	"bytes"
	"net"
	"testing"
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
