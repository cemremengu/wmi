package wmi

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"errors"
)

func gssWrapRC4(sessionKey, data []byte, seqNum uint32) ([]byte, []byte, error) {
	pad := (8 - (len(data) % 8)) & 0x7
	data = append(append([]byte(nil), data...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	tokenHeader := []byte{0x02, 0x01, 0x11, 0x00, 0x10, 0x00, 0xff, 0xff}
	sndSeq := seqBytes(seqNum, 0x00)
	confounder := randBytes(8)

	kSign := hmacMD5(sessionKey, []byte("signaturekey\x00"))
	md5Input := make([]byte, 0, 4+len(tokenHeader)+len(confounder)+len(data))
	md5Input = append(md5Input, le32(13)...)
	md5Input = append(md5Input, tokenHeader...)
	md5Input = append(md5Input, confounder...)
	md5Input = append(md5Input, data...)
	md5Pre := md5Digest(md5Input)
	sgn := hmacMD5(kSign, md5Pre[:])[:8]

	kSeqBase := hmacMD5(sessionKey, []byte{0, 0, 0, 0})
	kSeq := hmacMD5(kSeqBase, sgn)
	seqCipher, err := newRC4Cipher(kSeq)
	if err != nil {
		return nil, nil, err
	}
	encSndSeq := make([]byte, len(sndSeq))
	seqCipher.XORKeyStream(encSndSeq, sndSeq)

	kLocal := make([]byte, len(sessionKey))
	for i, b := range sessionKey {
		kLocal[i] = b ^ 0xf0
	}
	kCrypt := hmacMD5(hmacMD5(kLocal, []byte{0, 0, 0, 0}), binary.BigEndian.AppendUint32(nil, seqNum))
	rc4Cipher, err := newRC4Cipher(kCrypt)
	if err != nil {
		return nil, nil, err
	}
	encConf := make([]byte, len(confounder))
	rc4Cipher.XORKeyStream(encConf, confounder)
	cipherText := make([]byte, len(data))
	rc4Cipher.XORKeyStream(cipherText, data)

	tokenData := append(append(tokenHeader, encSndSeq...), sgn...)
	authData := append(append([]byte(nil), gssWrapHeader...), tokenData...)
	authData = append(authData, encConf...)
	return cipherText, authData, nil
}

func gssUnwrapRC4(sessionKey, cipherText, authData []byte) ([]byte, error) {
	if len(authData) < len(gssWrapHeader)+24+8 {
		return nil, errors.New("short GSS RC4 auth data")
	}
	tokenBytes := authData[len(gssWrapHeader):]
	sgn := tokenBytes[16:24]

	kSign := hmacMD5(sessionKey, []byte("signaturekey\x00"))
	kSeqBase := hmacMD5(sessionKey, []byte{0, 0, 0, 0})
	kSeq := hmacMD5(kSeqBase, sgn)
	seqCipher, err := newRC4Cipher(kSeq)
	if err != nil {
		return nil, err
	}
	sndSeq := make([]byte, 8)
	seqCipher.XORKeyStream(sndSeq, tokenBytes[8:16])

	kLocal := make([]byte, len(sessionKey))
	for i, b := range sessionKey {
		kLocal[i] = b ^ 0xf0
	}
	kCrypt := hmacMD5(hmacMD5(kLocal, []byte{0, 0, 0, 0}), sndSeq[:4])
	rc4Cipher, err := newRC4Cipher(kCrypt)
	if err != nil {
		return nil, err
	}
	decrypted := make([]byte, 8+len(cipherText))
	blob := make([]byte, 0, 8+len(cipherText))
	blob = append(blob, authData[len(authData)-8:]...)
	blob = append(blob, cipherText...)
	rc4Cipher.XORKeyStream(decrypted, blob)
	confounder, data := decrypted[:8], decrypted[8:]

	md5Input := make([]byte, 0, 4+8+len(confounder)+len(data))
	md5Input = append(md5Input, le32(13)...)
	md5Input = append(md5Input, tokenBytes[:8]...)
	md5Input = append(md5Input, confounder...)
	md5Input = append(md5Input, data...)
	md5Pre := md5Digest(md5Input)
	expected := hmacMD5(kSign, md5Pre[:])[:8]
	if !hmac.Equal(sgn, expected) {
		return nil, errors.New("gss rc4 integrity check failed")
	}
	if len(data) == 0 {
		return nil, nil
	}
	pad := int(data[len(data)-1])
	if pad > len(data) {
		return nil, errors.New("invalid gss rc4 padding")
	}
	return data[:len(data)-pad], nil
}

func gssWrapAES(sessionKey, data []byte, seqNum uint32) ([]byte, []byte, error) {
	pad := (16 - (len(data) % 16)) & 15
	header := append([]byte{0x05, 0x04, 0x06, 0xff}, make([]byte, 12)...)
	binary.BigEndian.PutUint16(header[4:6], uint16(pad))
	binary.BigEndian.PutUint16(header[6:8], 0)
	binary.BigEndian.PutUint64(header[8:16], uint64(seqNum))
	plaintext := append(append([]byte(nil), data...), bytes.Repeat([]byte{0xff}, pad)...)
	plaintext = append(plaintext, header...)

	rawCipher, err := encryptKerberosAESCTS(sessionKey, 24, plaintext, nil)
	if err != nil {
		return nil, nil, err
	}
	rrc := 28
	rotated := rotateRightBytes(rawCipher, rrc+pad)
	wireHeader := append([]byte{0x05, 0x04, 0x06, 0xff}, make([]byte, 12)...)
	binary.BigEndian.PutUint16(wireHeader[4:6], uint16(pad))
	binary.BigEndian.PutUint16(wireHeader[6:8], uint16(rrc))
	binary.BigEndian.PutUint64(wireHeader[8:16], uint64(seqNum))
	split := 16 + rrc + pad
	authData := append(append([]byte(nil), wireHeader...), rotated[:split]...)
	return rotated[split:], authData, nil
}

func gssUnwrapAES(sessionKey, cipherText, authData []byte) ([]byte, error) {
	return gssUnwrapAESUsage(sessionKey, cipherText, authData, 22)
}

func gssUnwrapAESUsage(sessionKey, cipherText, authData []byte, usage uint32) ([]byte, error) {
	if len(authData) < 16 {
		return nil, errors.New("short GSS AES auth data")
	}
	pad := int(binary.BigEndian.Uint16(authData[4:6]))
	rrc := int(binary.BigEndian.Uint16(authData[6:8]))
	rotated := append(append([]byte(nil), authData[16:]...), cipherText...)
	fullCipher := rotateLeftBytes(rotated, rrc+pad)
	decrypted, err := decryptKerberosAESCTS(sessionKey, usage, fullCipher)
	if err != nil {
		return nil, err
	}
	if len(decrypted) < 32+pad {
		return nil, errors.New("short decrypted GSS AES payload")
	}
	return decrypted[16 : len(decrypted)-16-pad], nil
}

func rotateRightBytes(data []byte, n int) []byte {
	if len(data) == 0 {
		return nil
	}
	n %= len(data)
	left := len(data) - n
	return append(append([]byte(nil), data[left:]...), data[:left]...)
}

func rotateLeftBytes(data []byte, n int) []byte {
	if len(data) == 0 {
		return nil
	}
	n %= len(data)
	return append(append([]byte(nil), data[n:]...), data[:n]...)
}
