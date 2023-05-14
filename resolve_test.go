package resolve

import (
	"bytes"
	"net"
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

func TestDecodeResponse(t *testing.T) {
	var (
		in         = []byte("`V\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00R\x9b\x00\x04]\xb8\xd8\"")
		wantHeader = Header{
			ID:           24662,
			Flags:        33152,
			NumQuestions: 1,
			NumAnswers:   1,
		}
		wantQuestion = Question{
			Name:  []byte("www.example.com"),
			Type:  TypeA,
			Class: ClassIN,
		}
		wantRecord = Record{
			Name:  []byte("www.example.com"),
			Type:  TypeA,
			Class: ClassIN,
			TTL:   21147,
			Data:  []byte("]\xb8\xd8\""),
		}
	)

	r := bytes.NewReader(in)

	gotHeader, err := DecodeHeader(r)
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if diff := cmp.Diff(wantHeader, gotHeader); diff != "" {
		t.Errorf("DecodeHeader mismatch (-want, +got):\n%s", diff)
	}

	gotQuestion, err := DecodeQuestion(r)
	if err != nil {
		t.Fatalf("DecodeQuestion: %v", err)
	}
	if diff := cmp.Diff(wantQuestion, gotQuestion); diff != "" {
		t.Errorf("DecodeQuestion mismatch (-want, +got):\n%s", diff)
	}

	gotRecord, err := DecodeRecord(r)
	if err != nil {
		t.Fatalf("DecodeRecord: %v", err)
	}
	if diff := cmp.Diff(wantRecord, gotRecord); diff != "" {
		t.Errorf("DecodeRecord mismatch (-want, +got):\n%s", diff)
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

func FuzzDecodeName(f *testing.F) {
	// DecodeName calls DecodeCompressedName and vice versa, so ensure no panic
	// or hang can occur.
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecodeName(bytes.NewReader(b))
	})
}
