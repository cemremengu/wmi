package wmi

import (
	"errors"
	"fmt"
)

type asn1Value struct {
	tag       byte
	headerLen int
	length    int
	content   []byte
	full      []byte
	next      int
}

func asn1Len(n int) []byte {
	if n < 0x80 {
		return []byte{mustByte(n)}
	}
	var tmp [8]byte
	i := len(tmp)
	for n > 0 {
		i--
		tmp[i] = mustByte(n)
		n >>= 8
	}
	out := []byte{0x80 | mustByte(len(tmp)-i)}
	return append(out, tmp[i:]...)
}

func asn1Tag(tagNum byte, content []byte) []byte {
	out := []byte{0xa0 | tagNum}
	out = append(out, asn1Len(len(content))...)
	return append(out, content...)
}

func asn1Seq(content []byte) []byte {
	out := []byte{0x30}
	out = append(out, asn1Len(len(content))...)
	return append(out, content...)
}

func asn1Int(val int) []byte {
	if val == 0 {
		return []byte{0x02, 0x01, 0x00}
	}
	var tmp [8]byte
	i := len(tmp)
	for v := val; v > 0; v >>= 8 {
		i--
		tmp[i] = byte(v)
	}
	body := tmp[i:]
	if len(body) == 0 {
		body = []byte{0}
	}
	if body[0]&0x80 != 0 {
		body = append([]byte{0}, body...)
	}
	out := []byte{0x02}
	out = append(out, asn1Len(len(body))...)
	return append(out, body...)
}

func asn1OctetString(val []byte) []byte {
	out := []byte{0x04}
	out = append(out, asn1Len(len(val))...)
	return append(out, val...)
}

func asn1GeneralizedTime(val []byte) []byte {
	out := []byte{0x18}
	out = append(out, asn1Len(len(val))...)
	return append(out, val...)
}

func asn1GeneralString(val []byte) []byte {
	out := []byte{0x1b}
	out = append(out, asn1Len(len(val))...)
	return append(out, val...)
}

func asn1App(tagNum byte, content []byte) []byte {
	out := []byte{0x60 | tagNum}
	out = append(out, asn1Len(len(content))...)
	return append(out, content...)
}

func getASN1Len(data []byte, pos int) (int, int, error) {
	if pos >= len(data) {
		return 0, 0, errors.New("asn1 length out of range")
	}
	b := data[pos]
	if b < 0x80 {
		return int(b), 1, nil
	}
	n := int(b & 0x7f)
	if n == 0 || pos+1+n > len(data) {
		return 0, 0, errors.New("invalid asn1 length")
	}
	l := 0
	for _, v := range data[pos+1 : pos+1+n] {
		l = (l << 8) | int(v)
	}
	return l, n + 1, nil
}

func parseASN1(data []byte, offset int) (asn1Value, error) {
	if offset >= len(data) {
		return asn1Value{}, errors.New("asn1 offset out of range")
	}
	length, ll, err := getASN1Len(data, offset+1)
	if err != nil {
		return asn1Value{}, err
	}
	headerLen := 1 + ll
	end := offset + headerLen + length
	if end > len(data) {
		return asn1Value{}, errors.New("short asn1 element")
	}
	return asn1Value{
		tag:       data[offset],
		headerLen: headerLen,
		length:    length,
		content:   data[offset+headerLen : end],
		full:      data[offset:end],
		next:      end,
	}, nil
}

func parseASN1Children(data []byte) ([]asn1Value, error) {
	out := make([]asn1Value, 0)
	for offset := 0; offset < len(data); {
		elem, err := parseASN1(data, offset)
		if err != nil {
			return nil, err
		}
		out = append(out, elem)
		offset = elem.next
	}
	return out, nil
}

func findASN1Child(data []byte, tag byte) (asn1Value, bool, error) {
	children, err := parseASN1Children(data)
	if err != nil {
		return asn1Value{}, false, err
	}
	for _, child := range children {
		if child.tag == tag {
			return child, true, nil
		}
	}
	return asn1Value{}, false, nil
}

func asn1IntegerValue(data []byte) (int, error) {
	elem, err := parseASN1(data, 0)
	if err != nil {
		return 0, err
	}
	if elem.tag != 0x02 {
		return 0, fmt.Errorf("expected integer tag, got %#x", elem.tag)
	}
	val := 0
	for _, b := range elem.content {
		val = (val << 8) | int(b)
	}
	return val, nil
}
