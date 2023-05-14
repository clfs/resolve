// Package resolve implements a toy DNS resolver.
package resolve

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand"
	"strings"
)

// Header is a DNS header.
type Header struct {
	ID             uint16
	Flags          uint16
	NumQuestions   uint16
	NumAnswers     uint16
	NumAuthorities uint16
	NumAdditionals uint16
}

// DecodeHeader decodes a DNS header.
func DecodeHeader(r io.Reader) (Header, error) {
	var h Header
	err := binary.Read(r, binary.BigEndian, &h)
	return h, err
}

// MarshalBinary implements encoding.BinaryMarshaler for Header.
func (h *Header) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.BigEndian, h)
	return buf.Bytes(), err
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler for Header.
func (h *Header) UnmarshalBinary(data []byte) error {
	return binary.Read(bytes.NewReader(data), binary.BigEndian, h)
}

// Question is a DNS question.
type Question struct {
	Name  []byte
	Type  Type
	Class Class
}

// DecodeQuestion decodes a DNS question.
func DecodeQuestion(r io.ReadSeeker) (Question, error) {
	var q Question

	name, err := DecodeName(r)
	if err != nil {
		return q, err
	}
	q.Name = name

	if err := binary.Read(r, binary.BigEndian, &q.Type); err != nil {
		return q, err
	}
	if err := binary.Read(r, binary.BigEndian, &q.Class); err != nil {
		return q, err
	}

	return q, nil
}

func (q *Question) MarshalBinary() ([]byte, error) {
	// binary.Write can only serialize types with known sizes.
	// https://cs.opensource.google/go/go/+/refs/tags/go1.20.4:src/encoding/binary/binary.go;l=450;drc=986b04c0f12efa1c57293f147a9e734ec71f0363
	var b []byte
	b = append(b, q.Name...)
	b = binary.BigEndian.AppendUint16(b, uint16(q.Type))
	b = binary.BigEndian.AppendUint16(b, uint16(q.Class))
	return b, nil
}

// EncodeDNSName encodes a domain name for DNS.
func EncodeDNSName(s string) []byte {
	var b []byte
	for _, part := range strings.Split(s, ".") {
		b = append(b, byte(len(part)))
		b = append(b, part...)
	}
	b = append(b, 0)
	return b
}

/*
def decode_name(reader):
    parts = []
    while (length := reader.read(1)[0]) != 0:
        if length & 0b1100_0000:
            parts.append(decode_compressed_name(length, reader))
            break
        else:
            parts.append(reader.read(length))
    return b".".join(parts)


def decode_compressed_name(length, reader):
    pointer_bytes = bytes([length & 0b0011_1111]) + reader.read(1)
    pointer = struct.unpack("!H", pointer_bytes)[0]
    current_pos = reader.tell()
    reader.seek(pointer)
    result = decode_name(reader)
    reader.seek(current_pos)
    return result
*/

// DecodeName decodes a DNS name.
func DecodeName(r io.ReadSeeker) ([]byte, error) {
	var (
		parts  [][]byte
		length = make([]byte, 1)
	)

loop:
	for {
		_, err := r.Read(length)
		if err != nil {
			return nil, err
		}

		switch n := int(length[0]); {
		case n == 0:
			break loop
		case n&0b1100_0000 != 0:
			part, err := DecodeCompressedName(n, r)
			if err != nil {
				return nil, err
			}
			parts = append(parts, part)
		default:
			part := make([]byte, n)
			if _, err := r.Read(part); err != nil {
				return nil, err
			}
			parts = append(parts, part)
		}
	}

	return bytes.Join(parts, []byte(".")), nil
}

// DecodeCompressedName decodes a compressed DNS name.
func DecodeCompressedName(length int, r io.ReadSeeker) ([]byte, error) {
	pointerBytes := make([]byte, 2)
	pointerBytes[0] = byte(length & 0b0011_1111)
	if _, err := r.Read(pointerBytes[1:]); err != nil {
		return nil, err
	}
	pointer := binary.BigEndian.Uint16(pointerBytes)

	restoreOffset, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}

	r.Seek(int64(pointer), io.SeekStart)

	res, err := DecodeName(r)
	if err != nil {
		return nil, err
	}

	r.Seek(restoreOffset, io.SeekStart)

	return res, nil
}

// A Type is a DNS record type.
type Type uint16

const TypeA Type = 1

// A Class is a DNS record class.
type Class uint16

const ClassIN Class = 1

// Flag constants.
const (
	FlagRecursionDesired uint16 = 1 << 8
)

// ID returns a random query ID.
func ID() uint16 {
	return uint16(rand.Int())
}

// NewQuery returns a new DNS query for a domain name and record type.
func NewQuery(domain string, t Type) ([]byte, error) {
	h := Header{
		ID:           ID(),
		NumQuestions: 1,
		Flags:        FlagRecursionDesired,
	}

	q := Question{
		Name:  EncodeDNSName(domain),
		Type:  t,
		Class: ClassIN,
	}

	hb, err := h.MarshalBinary()
	if err != nil {
		return nil, err
	}

	qb, err := q.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return append(hb, qb...), nil
}

type Record struct {
	Name  []byte
	Type  Type
	Class Class
	TTL   int
	Data  []byte
}
