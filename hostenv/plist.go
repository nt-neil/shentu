package hostenv

// Property lists, XML and binary (bplist00), read into plain Go values:
// map[string]any, []any, string, int64, float64, bool, []byte, time.Time.
// Enough for Info.plist and launchd jobs; it never writes.

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// ParsePlist decodes an XML or binary property list.
func ParsePlist(b []byte) (any, error) {
	if bytes.HasPrefix(b, []byte("bplist00")) {
		return parseBplist(b)
	}
	return parseXMLPlist(b)
}

// PlistString returns d[key] when it is a string.
func PlistString(d map[string]any, key string) string {
	s, _ := d[key].(string)
	return s
}

func parseXMLPlist(b []byte) (any, error) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = false
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("plist: %w", err)
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local != "plist" {
			return xmlValue(dec, se, 0)
		}
	}
}

func xmlValue(dec *xml.Decoder, se xml.StartElement, depth int) (any, error) {
	if depth > 64 {
		return nil, errors.New("plist: nested too deep")
	}
	switch se.Name.Local {
	case "dict":
		d := map[string]any{}
		key := ""
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				if t.Name.Local == "key" {
					if key, err = xmlText(dec); err != nil {
						return nil, err
					}
					continue
				}
				v, err := xmlValue(dec, t, depth+1)
				if err != nil {
					return nil, err
				}
				d[key] = v
			case xml.EndElement:
				return d, nil
			}
		}
	case "array":
		var a []any
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				v, err := xmlValue(dec, t, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			case xml.EndElement:
				return a, nil
			}
		}
	case "true", "false":
		if err := dec.Skip(); err != nil {
			return nil, err
		}
		return se.Name.Local == "true", nil
	}
	s, err := xmlText(dec)
	if err != nil {
		return nil, err
	}
	switch se.Name.Local {
	case "string":
		return s, nil
	case "integer":
		return strconv.ParseInt(strings.TrimSpace(s), 0, 64)
	case "real":
		return strconv.ParseFloat(strings.TrimSpace(s), 64)
	case "data":
		return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	case "date":
		return time.Parse(time.RFC3339, strings.TrimSpace(s))
	}
	return nil, fmt.Errorf("plist: unknown element <%s>", se.Name.Local)
}

// xmlText reads character data up to the end of the current element.
func xmlText(dec *xml.Decoder) (string, error) {
	var sb strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.CharData:
			sb.Write(t)
		case xml.EndElement:
			return sb.String(), nil
		case xml.StartElement:
			return "", fmt.Errorf("plist: <%s> inside a text element", t.Name.Local)
		}
	}
}

// bplist00: header, objects, offset table, 32-byte trailer.
type bplist struct {
	b       []byte
	offsets []uint64
	refSize int
	seen    map[uint64]bool // objects being decoded: a reference cycle is an error
	done    map[uint64]any  // objects decoded: a shared object is built once, so
	// a file of references to references cannot grow exponentially
	elems int // array and dictionary entries decoded, at most maxPlistElems
}

// maxPlistElems caps the array and dictionary entries of one binary plist:
// a small file of references to one object cannot fan out without end.
const maxPlistElems = 1 << 16

// grow counts n more entries.
func (p *bplist) grow(n uint64) error {
	if n > maxPlistElems || p.elems+int(n) > maxPlistElems {
		return errors.New("plist: too many elements")
	}
	p.elems += int(n)
	return nil
}

func parseBplist(b []byte) (any, error) {
	if len(b) < 8+32 {
		return nil, io.ErrUnexpectedEOF
	}
	t := b[len(b)-32:]
	offSize, refSize := int(t[6]), int(t[7])
	n, top, tableAt := binary.BigEndian.Uint64(t[8:]), binary.BigEndian.Uint64(t[16:]), binary.BigEndian.Uint64(t[24:])
	if offSize < 1 || offSize > 8 || refSize < 1 || refSize > 8 || n > uint64(len(b)) || top >= n ||
		tableAt > uint64(len(b)) || n*uint64(offSize) > uint64(len(b))-tableAt {
		return nil, errors.New("plist: bad binary trailer")
	}
	p := &bplist{b: b, refSize: refSize, seen: map[uint64]bool{}, done: map[uint64]any{}}
	for i := uint64(0); i < n; i++ {
		at := tableAt + i*uint64(offSize)
		p.offsets = append(p.offsets, beUint(b[at:at+uint64(offSize)]))
	}
	return p.object(top, 0)
}

func beUint(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

func (p *bplist) need(at, n uint64) error {
	if at > uint64(len(p.b)) || n > uint64(len(p.b))-at {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// count reads an object's length: the low nibble, or an int object after it.
func (p *bplist) count(at uint64, low byte) (n, next uint64, err error) {
	if low != 0xf {
		return uint64(low), at + 1, nil
	}
	if err := p.need(at+1, 1); err != nil {
		return 0, 0, err
	}
	m := p.b[at+1]
	if m>>4 != 0x1 {
		return 0, 0, errors.New("plist: bad length")
	}
	size := uint64(1) << (m & 0xf)
	if err := p.need(at+2, size); err != nil {
		return 0, 0, err
	}
	return beUint(p.b[at+2 : at+2+size]), at + 2 + size, nil
}

func (p *bplist) refs(at, n uint64) ([]uint64, error) {
	if n > uint64(len(p.b)) {
		return nil, io.ErrUnexpectedEOF
	}
	if err := p.need(at, n*uint64(p.refSize)); err != nil {
		return nil, err
	}
	out := make([]uint64, n)
	for i := range out {
		s := at + uint64(i*p.refSize)
		out[i] = beUint(p.b[s : s+uint64(p.refSize)])
	}
	return out, nil
}

func (p *bplist) object(ref uint64, depth int) (any, error) {
	if v, ok := p.done[ref]; ok {
		return v, nil
	}
	if ref >= uint64(len(p.offsets)) || depth > 64 || p.seen[ref] {
		return nil, errors.New("plist: bad object reference")
	}
	p.seen[ref] = true
	defer delete(p.seen, ref)
	v, err := p.decode(ref, depth)
	if err == nil {
		p.done[ref] = v
	}
	return v, err
}

func (p *bplist) decode(ref uint64, depth int) (any, error) {
	at := p.offsets[ref]
	if err := p.need(at, 1); err != nil {
		return nil, err
	}
	m := p.b[at]
	kind, low := m>>4, m&0xf
	switch kind {
	case 0x0:
		switch low {
		case 0x8:
			return false, nil
		case 0x9:
			return true, nil
		}
		return nil, nil
	case 0x1:
		size := uint64(1) << low
		if err := p.need(at+1, size); err != nil {
			return nil, err
		}
		if size > 8 { // 128-bit integers keep their low 64 bits
			at, size = at+size-8, 8
		}
		return int64(beUint(p.b[at+1 : at+1+size])), nil
	case 0x2:
		size := uint64(1) << low
		if err := p.need(at+1, size); err != nil {
			return nil, err
		}
		if size == 4 {
			return float64(math.Float32frombits(uint32(beUint(p.b[at+1 : at+5])))), nil
		}
		return math.Float64frombits(beUint(p.b[at+1 : at+1+size])), nil
	case 0x3:
		if err := p.need(at+1, 8); err != nil {
			return nil, err
		}
		secs := math.Float64frombits(beUint(p.b[at+1 : at+9]))
		return time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(secs * float64(time.Second))), nil
	}
	if kind == 0x8 { // UID (keyed archives)
		if err := p.need(at+1, uint64(low)+1); err != nil {
			return nil, err
		}
		return int64(beUint(p.b[at+1 : at+2+uint64(low)])), nil
	}
	n, next, err := p.count(at, low)
	if err != nil {
		return nil, err
	}
	switch kind {
	case 0x4:
		if err := p.need(next, n); err != nil {
			return nil, err
		}
		return append([]byte(nil), p.b[next:next+n]...), nil
	case 0x5:
		if err := p.need(next, n); err != nil {
			return nil, err
		}
		return string(p.b[next : next+n]), nil
	case 0x6:
		if n > uint64(len(p.b))/2 {
			return nil, io.ErrUnexpectedEOF
		}
		if err := p.need(next, 2*n); err != nil {
			return nil, err
		}
		u := make([]uint16, n)
		for i := range u {
			u[i] = binary.BigEndian.Uint16(p.b[next+uint64(2*i):])
		}
		return string(utf16.Decode(u)), nil
	case 0xa, 0xc:
		if err := p.grow(n); err != nil {
			return nil, err
		}
		rs, err := p.refs(next, n)
		if err != nil {
			return nil, err
		}
		a := make([]any, 0, len(rs))
		for _, r := range rs {
			v, err := p.object(r, depth+1)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
		return a, nil
	case 0xd:
		if err := p.grow(n); err != nil {
			return nil, err
		}
		ks, err := p.refs(next, n)
		if err != nil {
			return nil, err
		}
		vs, err := p.refs(next+n*uint64(p.refSize), n)
		if err != nil {
			return nil, err
		}
		d := make(map[string]any, n)
		for i := range ks {
			k, err := p.object(ks[i], depth+1)
			if err != nil {
				return nil, err
			}
			ks, ok := k.(string)
			if !ok {
				return nil, errors.New("plist: dictionary key is not a string")
			}
			v, err := p.object(vs[i], depth+1)
			if err != nil {
				return nil, err
			}
			d[ks] = v
		}
		return d, nil
	}
	return nil, fmt.Errorf("plist: unknown object type %#x", m)
}
