package wmi

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // NTLM requires MD5-based constructions for wire compatibility.
	crand "crypto/rand"
	"crypto/rc4" //nolint:gosec // NTLM and Kerberos RC4 profiles require RC4 for interoperability.
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4" //nolint:gosec,staticcheck // NTLM authentication requires MD4 for NT hash computation.
)

var referentSeq atomic.Uint32

func pad4(n int) int {
	return (4 - (n % 4)) % 4
}

func pad8(n int) int {
	return (8 - (n % 8)) % 8
}

func mustUint16(n int) uint16 { //nolint:gosec // This helper rejects values that exceed uint16 before converting.
	if n < 0 || n > math.MaxUint16 {
		panic(fmt.Sprintf("value %d exceeds uint16", n))
	}
	return uint16(n)
}

func mustUint32(n int) uint32 { //nolint:gosec // This helper rejects values that exceed uint32 before converting.
	if n < 0 || n > math.MaxUint32 {
		panic(fmt.Sprintf("value %d exceeds uint32", n))
	}
	return uint32(n)
}

func checkedUint32(
	n int,
) (uint32, error) { //nolint:gosec // This helper rejects values that exceed uint32 before converting.
	if n < 0 || n > math.MaxUint32 {
		return 0, fmt.Errorf("value %d exceeds uint32", n)
	}
	return uint32(n), nil
}

func checkedUint16(
	n uint32,
) (uint16, error) { //nolint:gosec // This helper rejects values that exceed uint16 before converting.
	if n > math.MaxUint16 {
		return 0, fmt.Errorf("value %d exceeds uint16", n)
	}
	return uint16(n), nil
}

func mustByte(n int) byte { //nolint:gosec // This helper rejects values that exceed a byte before converting.
	if n < 0 || n > math.MaxUint8 {
		panic(fmt.Sprintf("value %d exceeds byte", n))
	}
	return byte(n)
}

func mustByteFromUint16(
	n uint16,
) byte { //nolint:gosec // This helper rejects values that exceed a byte before converting.
	if n > math.MaxUint8 {
		panic(fmt.Sprintf("value %d exceeds byte", n))
	}
	return byte(n)
}

func lowByte(n int) byte { //nolint:gosec // This intentionally keeps the low 8 bits for one's-complement arithmetic.
	return byte(n & 0xff)
}

func mustUint(n int) uint { //nolint:gosec // Shift counts are validated to be non-negative before converting.
	if n < 0 {
		panic(fmt.Sprintf("negative shift count %d", n))
	}
	return uint(n)
}

func mustReadLE[T any](data []byte) T {
	var out T
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &out); err != nil {
		panic(err)
	}
	return out
}

func newMD5Hash() hash.Hash { //nolint:gosec // NTLM requires MD5-based constructions for wire compatibility.
	return md5.New() //nolint:gosec // NTLM requires MD5-based constructions for wire compatibility.
}

func md5Digest(data []byte) [16]byte { //nolint:gosec // NTLM and RC4-HMAC checksum formats use MD5 by specification.
	return md5.Sum(data) //nolint:gosec // NTLM and RC4-HMAC checksum formats use MD5 by specification.
}

func newRC4Cipher(
	key []byte,
) (*rc4.Cipher, error) { //nolint:gosec // NTLM and Kerberos RC4 profiles require RC4 for interoperability.
	return rc4.NewCipher(key) //nolint:gosec // NTLM and Kerberos RC4 profiles require RC4 for interoperability.
}

func genReferentID() uint32 {
	if v := referentSeq.Add(1); v != 0 {
		return v
	}
	return referentSeq.Add(1)
}

func genCID() []byte {
	b := make([]byte, 16)
	_, _ = crand.Read(b)
	return b
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = crand.Read(b)
	return b
}

func getNull() []byte {
	return []byte{0, 0, 0, 0}
}

func isFQDN(target string) bool {
	return net.ParseIP(target) == nil
}

func uuidToBin(uuid string) ([]byte, error) {
	parts := strings.Split(uuid, "-")
	if len(parts) != 5 {
		return nil, fmt.Errorf("invalid UUID %q", uuid)
	}
	if len(parts[4]) != 12 {
		return nil, fmt.Errorf("invalid UUID %q", uuid)
	}
	var (
		u1 uint64
		u2 uint64
		u3 uint64
		u4 uint64
		u5 uint64
	)
	var err error
	if u1, err = strconv.ParseUint(parts[0], 16, 32); err != nil {
		return nil, err
	}
	if u2, err = strconv.ParseUint(parts[1], 16, 16); err != nil {
		return nil, err
	}
	if u3, err = strconv.ParseUint(parts[2], 16, 16); err != nil {
		return nil, err
	}
	if u4, err = strconv.ParseUint(parts[3], 16, 16); err != nil {
		return nil, err
	}
	if u5, err = strconv.ParseUint(parts[4], 16, 48); err != nil {
		return nil, err
	}
	out := make([]byte, 16)
	binary.LittleEndian.PutUint32(out[0:4], uint32(u1))
	binary.LittleEndian.PutUint16(out[4:6], uint16(u2))
	binary.LittleEndian.PutUint16(out[6:8], uint16(u3))
	binary.BigEndian.PutUint16(out[8:10], uint16(u4))
	out[10] = byte(u5 >> 40)
	out[11] = byte(u5 >> 32) //nolint:gosec // Extracting individual bytes from a 48-bit UUID field.
	out[12] = byte(u5 >> 24) //nolint:gosec // Extracting individual bytes from a 48-bit UUID field.
	out[13] = byte(u5 >> 16) //nolint:gosec // Extracting individual bytes from a 48-bit UUID field.
	out[14] = byte(u5 >> 8)  //nolint:gosec // Extracting individual bytes from a 48-bit UUID field.
	out[15] = byte(u5)       //nolint:gosec // Extracting individual bytes from a 48-bit UUID field.
	return out, nil
}

func mustUUIDToBin(uuid string) []byte {
	b, err := uuidToBin(uuid)
	if err != nil {
		panic(err)
	}
	return b
}

func verToBin(ver string) ([]byte, error) {
	parts := strings.Split(ver, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid version %q", ver)
	}
	ma, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return nil, err
	}
	mi, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 4)
	binary.LittleEndian.PutUint16(out[0:2], uint16(ma))
	binary.LittleEndian.PutUint16(out[2:4], uint16(mi))
	return out, nil
}

func uuidVerToBin(uuid, ver string) ([]byte, error) {
	ub, err := uuidToBin(uuid)
	if err != nil {
		return nil, err
	}
	vb, err := verToBin(ver)
	if err != nil {
		return nil, err
	}
	return append(ub, vb...), nil
}

func mustUUIDVerToBin(uuid, ver string) []byte {
	b, err := uuidVerToBin(uuid, ver)
	if err != nil {
		panic(err)
	}
	return b
}

func uuidPart(uuidVer []byte) []byte {
	return append([]byte(nil), uuidVer[:16]...)
}

func binToUUID(data []byte, offset int) string {
	u1 := binary.LittleEndian.Uint32(data[offset : offset+4])
	u2 := binary.LittleEndian.Uint16(data[offset+4 : offset+6])
	u3 := binary.LittleEndian.Uint16(data[offset+6 : offset+8])
	u4 := binary.BigEndian.Uint16(data[offset+8 : offset+10])
	return fmt.Sprintf(
		"%08X-%04X-%04X-%04X-%s",
		u1,
		u2,
		u3,
		u4,
		strings.ToUpper(hex.EncodeToString(data[offset+10:offset+16])),
	)
}

func decodeEncodedString(data []byte, offset int) (string, int, error) {
	if offset >= len(data) {
		return "", offset, errors.New("encoded string offset out of range")
	}
	flags := data[offset]
	offset++
	if flags == 0 {
		end := bytes.IndexByte(data[offset:], 0)
		if end < 0 {
			return "", offset, errors.New("compressed string terminator not found")
		}
		raw := data[offset : offset+end]
		if allASCII(raw) {
			return string(raw), offset + end + 1, nil
		}
		u16 := make([]uint16, len(raw))
		for i, b := range raw {
			u16[i] = uint16(b)
		}
		return string(utf16.Decode(u16)), offset + end + 1, nil
	}

	for end := offset; end+1 < len(data); end += 2 {
		if data[end] == 0 && data[end+1] == 0 {
			raw := data[offset:end]
			if len(raw)%2 != 0 {
				raw = raw[:len(raw)-1]
			}
			u16 := make([]uint16, len(raw)/2)
			for i := range u16 {
				u16[i] = binary.LittleEndian.Uint16(raw[i*2:])
			}
			return string(utf16.Decode(u16)), end + 2, nil
		}
	}
	return "", offset, errors.New("unicode string terminator not found")
}

func allASCII(b []byte) bool {
	for _, v := range b {
		if v >= 0x80 {
			return false
		}
	}
	return true
}

func readStringBindings(data []byte, offset int) ([][2]any, int, error) {
	var bindings [][2]any
	for offset+2 <= len(data) {
		towerID := binary.LittleEndian.Uint16(data[offset:])
		offset += 2
		if towerID == 0 {
			return bindings, offset, nil
		}
		end := -1
		for i := offset; i+1 < len(data); i += 2 {
			if data[i] == 0 && data[i+1] == 0 {
				end = i + 2
				break
			}
		}
		if end < 0 {
			return nil, offset, errors.New("malformed string binding")
		}
		raw := data[offset:end]
		u16 := make([]uint16, len(raw)/2)
		for i := range u16 {
			u16[i] = binary.LittleEndian.Uint16(raw[i*2:])
		}
		s := strings.TrimRight(string(utf16.Decode(u16)), "\x00")
		bindings = append(bindings, [2]any{towerID, s})
		offset = end
	}
	return bindings, offset, nil
}

func wordStr(s *string) []byte {
	if s == nil {
		return getNull()
	}
	enc := utf16Bytes(*s + "\x00")
	out := make([]byte, 16+len(enc)+pad4(len(enc)))
	binary.LittleEndian.PutUint32(out[0:4], genReferentID())
	binary.LittleEndian.PutUint32(out[4:8], mustUint32(len(enc)/2))
	binary.LittleEndian.PutUint32(out[8:12], mustUint32(len(enc)))
	binary.LittleEndian.PutUint32(out[12:16], mustUint32(len(enc)/2))
	copy(out[16:], enc)
	for i := 16 + len(enc); i < len(out); i++ {
		out[i] = 0xbf
	}
	return out
}

func lpwStr(s *string) []byte {
	if s == nil {
		return getNull()
	}
	enc := utf16Bytes(*s + "\x00")
	out := make([]byte, 16+len(enc)+pad4(len(enc)))
	binary.LittleEndian.PutUint32(out[0:4], genReferentID())
	binary.LittleEndian.PutUint32(out[4:8], mustUint32(len(enc)/2))
	binary.LittleEndian.PutUint32(out[8:12], 0)
	binary.LittleEndian.PutUint32(out[12:16], mustUint32(len(enc)/2))
	copy(out[16:], enc)
	for i := 16 + len(enc); i < len(out); i++ {
		out[i] = 0xbf
	}
	return out
}

func utf16Bytes(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	out := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(out[i*2:], v)
	}
	return out
}

func hmacMD5(key, data []byte) []byte {
	h := hmac.New(newMD5Hash, key)
	_, _ = h.Write(data)
	return h.Sum(nil)
}

func ntOWFv2(user, password string, domain []byte) []byte {
	hash := hmac.New(newMD5Hash, computeNTHash(password))
	_, _ = hash.Write(utf16Bytes(strings.ToUpper(user)))
	_, _ = hash.Write(domain)
	return hash.Sum(nil)
}

func encryptedSessionKey(keyExchangeKey, exportedSessionKey []byte) []byte {
	c, err := newRC4Cipher(keyExchangeKey)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(exportedSessionKey))
	c.XORKeyStream(out, exportedSessionKey)
	return out
}

func computeNTHash(password string) []byte {
	h := md4.New() //nolint:gosec // NTLM authentication requires MD4 for NT hash computation.
	_, _ = h.Write(utf16Bytes(password))
	return h.Sum(nil)
}

type rc4Func struct {
	c *rc4.Cipher
}

func newRC4Func(key []byte) *rc4Func {
	c, err := newRC4Cipher(key)
	if err != nil {
		panic(err)
	}
	return &rc4Func{c: c}
}

func (r *rc4Func) Apply(src []byte) []byte {
	out := make([]byte, len(src))
	r.c.XORKeyStream(out, src)
	return out
}

func signKey(flags uint32, randomSessionKey []byte, clientMode bool) []byte {
	if flags&ntlmSSPNegotiateExtendedSessionSecurity == 0 {
		return nil
	}
	const (
		clientMagic = "session key to client-to-server signing key magic constant\x00"
		serverMagic = "session key to server-to-client signing key magic constant\x00"
	)
	h := newMD5Hash()
	_, _ = h.Write(randomSessionKey)
	if clientMode {
		_, _ = h.Write([]byte(clientMagic))
	} else {
		_, _ = h.Write([]byte(serverMagic))
	}
	return h.Sum(nil)
}

func sealKey(flags uint32, randomSessionKey []byte, clientMode bool) []byte {
	const (
		clientMagic = "session key to client-to-server sealing key magic constant\x00"
		serverMagic = "session key to server-to-client sealing key magic constant\x00"
	)
	var base []byte
	switch {
	case flags&ntlmSSPNegotiateExtendedSessionSecurity != 0 && flags&ntlmSSPNegotiate128 != 0:
		base = randomSessionKey
	case flags&ntlmSSPNegotiateExtendedSessionSecurity != 0 && flags&ntlmSSPNegotiate56 != 0:
		base = randomSessionKey[:7]
	case flags&ntlmSSPNegotiateExtendedSessionSecurity != 0:
		base = randomSessionKey[:5]
	case flags&ntlmSSPNegotiate56 != 0:
		return append(append([]byte(nil), randomSessionKey[:7]...), 0xa0)
	default:
		return append(append([]byte(nil), randomSessionKey[:5]...), []byte{0xe5, 0x38, 0xb0}...)
	}
	h := newMD5Hash()
	_, _ = h.Write(base)
	if clientMode {
		_, _ = h.Write([]byte(clientMagic))
	} else {
		_, _ = h.Write([]byte(serverMagic))
	}
	return h.Sum(nil)
}

func windowsFileTimeNow() []byte {
	ts := max(time.Now().UTC().Unix(), 0)
	ft := uint64(116444736000000000) + uint64(ts)*10000000
	out := make([]byte, 8)
	binary.LittleEndian.PutUint64(out, ft)
	return out
}
