// Package resolve implements a toy DNS resolver.
package resolve

import (
	"encoding/binary"
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

func (h Header) MarshalBinary() ([]byte, error) {
	var b []byte
	b = binary.BigEndian.AppendUint16(b, h.ID)
	b = binary.BigEndian.AppendUint16(b, h.Flags)
	b = binary.BigEndian.AppendUint16(b, h.NumQuestions)
	b = binary.BigEndian.AppendUint16(b, h.NumAnswers)
	b = binary.BigEndian.AppendUint16(b, h.NumAuthorities)
	b = binary.BigEndian.AppendUint16(b, h.NumAdditionals)
	return b, nil
}

// Question is a DNS question.
type Question struct {
	Name  []byte
	Type  Type
	Class Class
}

func (q Question) MarshalBinary() ([]byte, error) {
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
