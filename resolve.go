// Package resolve implements a toy DNS resolver.
package resolve

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
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
			break loop
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

	if _, err := r.Seek(int64(pointer), io.SeekStart); err != nil {
		return nil, err
	}

	res, err := DecodeName(r)
	if err != nil {
		return nil, err
	}

	if _, err := r.Seek(restoreOffset, io.SeekStart); err != nil {
		return nil, err
	}

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

// Record represents a DNS record.
type Record struct {
	Name  []byte
	Type  Type
	Class Class
	TTL   uint32
	Data  []byte
}

// DecodeRecord decodes a DNS record.
func DecodeRecord(r io.ReadSeeker) (Record, error) {
	var record Record

	name, err := DecodeName(r)
	if err != nil {
		return record, err
	}
	record.Name = name

	buf := make([]byte, 10)
	if _, err := r.Read(buf); err != nil {
		return record, err
	}

	record.Type = Type(binary.BigEndian.Uint16(buf[0:]))
	record.Class = Class(binary.BigEndian.Uint16(buf[2:]))
	record.TTL = binary.BigEndian.Uint32(buf[4:])

	dataLen := binary.BigEndian.Uint16(buf[8:])
	data := make([]byte, dataLen)
	if _, err := r.Read(data); err != nil {
		return record, err
	}
	record.Data = data

	return record, nil
}

// Packet represents a DNS packet.
type Packet struct {
	Header      Header
	Questions   []Question
	Answers     []Record
	Authorities []Record
	Additionals []Record
}

// DecodePacket decodes a DNS packet.
func DecodePacket(r io.ReadSeeker) (*Packet, error) {
	var p Packet

	header, err := DecodeHeader(r)
	if err != nil {
		return nil, err
	}
	p.Header = header

	for i := 0; i < int(p.Header.NumQuestions); i++ {
		q, err := DecodeQuestion(r)
		if err != nil {
			return nil, err
		}
		p.Questions = append(p.Questions, q)
	}

	for i := 0; i < int(p.Header.NumAnswers); i++ {
		rec, err := DecodeRecord(r)
		if err != nil {
			return nil, err
		}
		p.Answers = append(p.Answers, rec)
	}

	for i := 0; i < int(p.Header.NumAuthorities); i++ {
		rec, err := DecodeRecord(r)
		if err != nil {
			return nil, err
		}
		p.Authorities = append(p.Authorities, rec)
	}

	for i := 0; i < int(p.Header.NumAdditionals); i++ {
		rec, err := DecodeRecord(r)
		if err != nil {
			return nil, err
		}
		p.Additionals = append(p.Additionals, rec)
	}

	return &p, nil
}

func LookupDomain(name string) (netip.Addr, error) {
	query, err := NewQuery(name, TypeA)
	if err != nil {
		return netip.Addr{}, err
	}

	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return netip.Addr{}, err
	}

	if _, err := conn.Write(query); err != nil {
		return netip.Addr{}, err
	}

	buf := make([]byte, 1024)
	if _, err := conn.Read(buf); err != nil {
		return netip.Addr{}, err
	}

	response, err := DecodePacket(bytes.NewReader(buf))
	if err != nil {
		return netip.Addr{}, err
	}

	if len(response.Answers) == 0 {
		return netip.Addr{}, fmt.Errorf("no answers")
	}

	ipData := response.Answers[0].Data
	ip, ok := netip.AddrFromSlice(ipData)
	if !ok {
		return netip.Addr{}, fmt.Errorf("invalid ip: %x", ipData)
	}
	return ip, nil
}
