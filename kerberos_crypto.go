package wmi

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha1" //nolint:gosec // Kerberos AES string-to-key and HMAC use SHA-1 by spec.
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

func newSHA1Hash() hash.Hash { //nolint:gosec // Kerberos AES string-to-key and HMAC use SHA-1 by spec.
	return sha1.New() //nolint:gosec // Kerberos AES string-to-key and HMAC use SHA-1 by spec.
}

func nFold(in []byte, nbytes int) []byte {
	if len(in) == 0 || nbytes == 0 {
		return nil
	}
	rotateRight := func(src []byte, nbits int) []byte {
		width := len(src) * 8
		nbits %= width
		if nbits == 0 {
			return append([]byte(nil), src...)
		}
		v := new(big.Int).SetBytes(src)
		mask := new(big.Int).Lsh(big.NewInt(1), mustUint(width))
		mask.Sub(mask, big.NewInt(1))
		right := new(big.Int).Rsh(v, mustUint(nbits))
		left := new(big.Int).Lsh(v, mustUint(width-nbits))
		right.Or(right, left)
		right.And(right, mask)
		out := right.Bytes()
		if len(out) < len(src) {
			out = append(bytes.Repeat([]byte{0}, len(src)-len(out)), out...)
		}
		return out
	}
	addOnesComplement := func(a, b []byte) []byte {
		out := make([]byte, len(a))
		carry := 0
		for i := len(a) - 1; i >= 0; i-- {
			sum := int(a[i]) + int(b[i]) + carry
			out[i] = lowByte(sum)
			carry = sum >> 8
		}
		for carry > 0 {
			for i := len(out) - 1; i >= 0; i-- {
				sum := int(out[i]) + carry
				out[i] = lowByte(sum)
				carry = sum >> 8
				if carry == 0 {
					break
				}
			}
		}
		return out
	}
	lcm := len(in) * nbytes / gcd(len(in), nbytes)
	bigStr := make([]byte, 0, lcm)
	cur := append([]byte(nil), in...)
	for len(bigStr) < lcm {
		bigStr = append(bigStr, cur...)
		cur = rotateRight(cur, 13)
	}
	out := make([]byte, nbytes)
	for i := 0; i < len(bigStr); i += nbytes {
		out = addOnesComplement(out, bigStr[i:i+nbytes])
	}
	return out
}

func deriveKey(baseKey, constant []byte) []byte {
	nfolded := nFold(constant, aes.BlockSize)
	block, _ := aes.NewCipher(baseKey)
	b1 := make([]byte, aes.BlockSize)
	block.Encrypt(b1, nfolded)
	if len(baseKey) == aes.BlockSize {
		return b1
	}
	b2 := make([]byte, aes.BlockSize)
	block.Encrypt(b2, b1)
	return append(b1, b2...)
}

func deriveUsageKey(baseKey []byte, usage uint32, payload byte) []byte {
	constant := make([]byte, 5)
	binary.BigEndian.PutUint32(constant[:4], usage)
	constant[4] = payload
	return deriveKey(baseKey, constant)
}

func aesCTSEncrypt(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	n := len(plain)
	if n == 0 {
		return nil, nil
	}
	if n <= aes.BlockSize {
		padded := append([]byte(nil), plain...)
		if len(padded) < aes.BlockSize {
			padded = append(padded, bytes.Repeat([]byte{0}, aes.BlockSize-len(padded))...)
		}
		out := make([]byte, aes.BlockSize)
		block.Encrypt(out, padded)
		return out[:n], nil
	}
	if n%aes.BlockSize == 0 {
		out := make([]byte, n)
		cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(out, plain)
		if n == aes.BlockSize {
			return out, nil
		}
		return append(
			append([]byte(nil), out[:n-2*aes.BlockSize]...),
			append(out[n-aes.BlockSize:], out[n-2*aes.BlockSize:n-aes.BlockSize]...)...), nil
	}
	padLen := aes.BlockSize - (n % aes.BlockSize)
	padded := append(append([]byte(nil), plain...), bytes.Repeat([]byte{0}, padLen)...)
	full := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(full, padded)
	lastStart := len(full) - aes.BlockSize
	prevStart := lastStart - aes.BlockSize
	return append(
		append([]byte(nil), full[:prevStart]...),
		append(full[lastStart:], full[prevStart:prevStart+n%aes.BlockSize]...)...), nil
}

func aesCTSDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	n := len(ciphertext)
	if n == 0 {
		return nil, nil
	}
	if n <= aes.BlockSize {
		padded := make([]byte, aes.BlockSize)
		copy(padded, ciphertext)
		out := make([]byte, aes.BlockSize)
		block.Decrypt(out, padded)
		return out[:n], nil
	}
	if n%aes.BlockSize == 0 {
		full := append([]byte(nil), ciphertext...)
		if n > aes.BlockSize {
			copy(full[n-2*aes.BlockSize:n-aes.BlockSize], ciphertext[n-aes.BlockSize:])
			copy(full[n-aes.BlockSize:], ciphertext[n-2*aes.BlockSize:n-aes.BlockSize])
		}
		out := make([]byte, n)
		cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(out, full)
		return out, nil
	}
	m := ((n - aes.BlockSize - 1) / aes.BlockSize) * aes.BlockSize
	var prefix []byte
	iv := make([]byte, aes.BlockSize)
	if m > 0 {
		prefix = make([]byte, m)
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(prefix, ciphertext[:m])
		copy(iv, ciphertext[m-aes.BlockSize:m])
	}
	cnMinus1 := ciphertext[m : m+aes.BlockSize]
	cn := ciphertext[m+aes.BlockSize:]
	tmp := make([]byte, aes.BlockSize)
	block.Decrypt(tmp, cnMinus1)
	pn := xorBytes(tmp[:len(cn)], cn)
	lastBlock := append(append([]byte(nil), cn...), tmp[len(cn):]...)
	tmp2 := make([]byte, aes.BlockSize)
	block.Decrypt(tmp2, lastBlock)
	pnMinus1 := xorBytes(tmp2, iv)
	return append(append(prefix, pnMinus1...), pn...), nil
}

func encryptKerberosAESCTS(sessionKey []byte, usage uint32, plainText, confounder []byte) ([]byte, error) {
	if confounder == nil {
		confounder = randBytes(aes.BlockSize)
	}
	plaintext := append(append([]byte(nil), confounder...), plainText...)
	ki := deriveUsageKey(sessionKey, usage, 0x55)
	ke := deriveUsageKey(sessionKey, usage, 0xaa)
	mac := hmac.New(newSHA1Hash, ki)
	_, _ = mac.Write(plaintext)
	ctext, err := aesCTSEncrypt(ke, plaintext)
	if err != nil {
		return nil, err
	}
	return append(ctext, mac.Sum(nil)[:12]...), nil
}

func decryptKerberosAESCTS(key []byte, usage uint32, cipherText []byte) ([]byte, error) {
	if len(cipherText) < 12 {
		return nil, errors.New("short kerberos aes payload")
	}
	ki := deriveUsageKey(key, usage, 0x55)
	ke := deriveUsageKey(key, usage, 0xaa)
	data, checksum := cipherText[:len(cipherText)-12], cipherText[len(cipherText)-12:]
	plain, err := aesCTSDecrypt(ke, data)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(newSHA1Hash, ki)
	_, _ = mac.Write(plain)
	if !hmac.Equal(mac.Sum(nil)[:12], checksum) {
		return nil, errors.New("kerberos aes checksum mismatch")
	}
	return plain, nil
}

func encryptKerberosRC4(sessionKey []byte, usage uint32, plainText []byte) ([]byte, error) {
	confounder := randBytes(8)
	payload := append(append([]byte(nil), confounder...), plainText...)
	usageBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(usageBytes, usage)
	k1 := hmacMD5(sessionKey, usageBytes)
	checksum := hmacMD5(k1, payload)
	k3 := hmacMD5(k1, checksum)
	c, err := newRC4Cipher(k3)
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, len(payload))
	c.XORKeyStream(encrypted, payload)
	return append(checksum, encrypted...), nil
}

func decryptKerberosRC4(key []byte, usage uint32, data []byte) ([]byte, error) {
	if len(data) < 24 {
		return nil, errors.New("short kerberos rc4 payload")
	}
	checksum, encrypted := data[:16], data[16:]
	usageBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(usageBytes, usage)
	k1 := hmacMD5(key, usageBytes)
	k3 := hmacMD5(k1, checksum)
	c, err := newRC4Cipher(k3)
	if err != nil {
		return nil, err
	}
	decrypted := make([]byte, len(encrypted))
	c.XORKeyStream(decrypted, encrypted)
	if len(decrypted) < 8 {
		return nil, errors.New("short kerberos rc4 plaintext")
	}
	return decrypted[8:], nil
}

func aesStringToKey(password, salt string, keyLen int) []byte {
	return aesStringToKeyIter(password, salt, keyLen, 4096)
}

func aesStringToKeyIter(password, salt string, keyLen, iterations int) []byte {
	tkey, err := pbkdf2.Key(newSHA1Hash, password, []byte(salt), iterations, keyLen)
	if err != nil {
		return nil
	}
	return deriveKey(tkey, []byte("kerberos"))
}

func readSessionKey(data []byte) ([]byte, error) {
	_, key, err := readEncryptionKey(data)
	return key, err
}

func readEncryptionKey(data []byte) (int, []byte, error) {
	if len(data) < aes.BlockSize {
		return 0, nil, errors.New("short encrypted reply")
	}
	root, err := parseASN1(data[aes.BlockSize:], 0)
	if err != nil {
		return 0, nil, err
	}
	seq, err := parseASN1(root.content, 0)
	if err != nil {
		return 0, nil, err
	}
	keyField, ok, err := findASN1Child(seq.content, 0xa0)
	if err != nil {
		return 0, nil, err
	}
	if !ok {
		return 0, nil, errors.New("session key field not found")
	}
	keySeq, err := parseASN1(keyField.content, 0)
	if err != nil {
		return 0, nil, err
	}
	etypeField, ok, err := findASN1Child(keySeq.content, 0xa0)
	if err != nil {
		return 0, nil, err
	}
	if !ok {
		return 0, nil, errors.New("session key type not found")
	}
	etype, err := asn1IntegerValue(etypeField.content)
	if err != nil {
		return 0, nil, err
	}
	valueField, ok, err := findASN1Child(keySeq.content, 0xa1)
	if err != nil {
		return 0, nil, err
	}
	if !ok {
		return 0, nil, errors.New("session key value not found")
	}
	octets, err := parseASN1(valueField.content, 0)
	if err != nil {
		return 0, nil, err
	}
	if octets.tag != 0x04 {
		return 0, nil, fmt.Errorf("unexpected session key tag %#x", octets.tag)
	}
	return etype, append([]byte(nil), octets.content...), nil
}

func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}
