package wmi

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type ntlmChallenge struct {
	negotiateFlags  uint32
	serverChallenge []byte
	targetInfo      []byte
}

type avPairs struct {
	pairs map[uint16][]byte
}

func parseAVPairs(data []byte) *avPairs {
	p := &avPairs{pairs: make(map[uint16][]byte)}
	for off := 0; off+4 <= len(data); {
		ftype := binary.LittleEndian.Uint16(data[off:])
		l := int(binary.LittleEndian.Uint16(data[off+2:]))
		off += 4
		if off+l > len(data) {
			break
		}
		p.pairs[ftype] = append([]byte(nil), data[off:off+l]...)
		off += l
		if ftype == ntlmSSPAvEOL {
			break
		}
	}
	return p
}

func (p *avPairs) setPair(ftype uint16, content []byte) {
	p.pairs[ftype] = append([]byte(nil), content...)
}

func (p *avPairs) setTargetName() {
	host := p.pairs[ntlmSSPAvHostname]
	if len(host) == 0 {
		return
	}
	p.setPair(ntlmSSPAvTargetName, append(utf16Bytes("cifs/"), host...))
}

func (p *avPairs) getOrSetTime() []byte {
	if v := p.pairs[ntlmSSPAvTime]; len(v) > 0 {
		return v
	}
	v := windowsFileTimeNow()
	p.setPair(ntlmSSPAvTime, v)
	return v
}

func (p *avPairs) bytes() []byte {
	var out []byte
	for i := uint16(1); i <= ntlmSSPAvTargetName; i++ {
		v, ok := p.pairs[i]
		if !ok {
			continue
		}
		var hdr [4]byte
		binary.LittleEndian.PutUint16(hdr[0:2], i)
		binary.LittleEndian.PutUint16(hdr[2:4], mustUint16(len(v)))
		out = append(out, hdr[:]...)
		out = append(out, v...)
	}
	out = append(out, 0, 0, 0, 0)
	return out
}

func buildNTLMNegotiate() ([]byte, uint32) {
	flags := uint32(
		ntlmSSPNegotiateKeyExch |
			ntlmSSPNegotiateSign |
			ntlmSSPNegotiateAlwaysSign |
			ntlmSSPNegotiateSeal |
			ntlmSSPNegotiateTargetInfo |
			ntlmSSPNegotiateNTLM |
			ntlmSSPNegotiateExtendedSessionSecurity |
			ntlmSSPRequestTarget |
			ntlmSSPNegotiateUnicode |
			ntlmSSPNegotiate128 |
			ntlmSSPNegotiate56,
	)
	buf := bytes.NewBuffer(make([]byte, 0, 40))
	buf.WriteString("NTLMSSP\x00")
	_ = binary.Write(buf, binary.LittleEndian, uint32(1))
	_ = binary.Write(buf, binary.LittleEndian, flags)
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(buf, binary.LittleEndian, uint32(32))
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(buf, binary.LittleEndian, uint32(32))
	return buf.Bytes(), flags
}

func parseNTLMChallenge(data []byte) (*ntlmChallenge, error) {
	if len(data) < 48 || !bytes.HasPrefix(data, []byte("NTLMSSP\x00")) {
		return nil, errors.New("invalid NTLM challenge")
	}
	targetNameLen := int(binary.LittleEndian.Uint16(data[12:14]))
	targetNameOff := int(binary.LittleEndian.Uint32(data[16:20]))
	flags := binary.LittleEndian.Uint32(data[20:24])
	serverChallenge := append([]byte(nil), data[24:32]...)
	targetInfoLen := int(binary.LittleEndian.Uint16(data[40:42]))
	targetInfoOff := int(binary.LittleEndian.Uint32(data[44:48]))
	if targetNameOff+targetNameLen > len(data) || targetInfoOff+targetInfoLen > len(data) {
		return nil, errors.New("invalid NTLM challenge offsets")
	}
	_ = data[targetNameOff : targetNameOff+targetNameLen]
	return &ntlmChallenge{
		negotiateFlags:  flags,
		serverChallenge: serverChallenge,
		targetInfo:      append([]byte(nil), data[targetInfoOff:targetInfoOff+targetInfoLen]...),
	}, nil
}

func buildNTLMAuthenticate(
	user, password, domain, workstation string,
	flags uint32,
	challenge *ntlmChallenge,
) ([]byte, uint32, []byte) {
	domainBytes := utf16Bytes(domain)
	userBytes := utf16Bytes(user)
	workstationBytes := utf16Bytes(workstation)

	responseKeyNT := ntOWFv2(user, password, domainBytes)
	av := parseAVPairs(challenge.targetInfo)
	av.setTargetName()
	avTime := av.getOrSetTime()
	clientChallenge := randBytes(8)
	serverName := av.bytes()

	temp := make([]byte, 0, 48+len(serverName))
	temp = append(temp, []byte{0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
	temp = append(temp, avTime...)
	temp = append(temp, clientChallenge...)
	temp = append(temp, 0, 0, 0, 0)
	temp = append(temp, serverName...)
	temp = append(temp, 0, 0, 0, 0)

	ntProof := hmacMD5(responseKeyNT, append(append([]byte(nil), challenge.serverChallenge...), temp...))
	lmResp := append(
		hmacMD5(responseKeyNT, append(append([]byte(nil), challenge.serverChallenge...), clientChallenge...)),
		clientChallenge...)
	ntResp := append(append([]byte(nil), ntProof...), temp...)
	sessionBaseKey := hmacMD5(responseKeyNT, ntProof)

	exportedSessionKey := sessionBaseKey
	encryptedRandomSessionKey := []byte(nil)
	if flags&ntlmSSPNegotiateKeyExch != 0 {
		exportedSessionKey = randBytes(16)
		encryptedRandomSessionKey = encryptedSessionKey(sessionBaseKey, exportedSessionKey)
	}

	if len(workstationBytes) > 0 {
		flags |= ntlmSSPNegotiateOEMWorkstationSupplied
	}
	if len(domainBytes) > 0 {
		flags |= ntlmSSPNegotiateOEMDomainSupplied
	}

	base := 64
	domainOff := base
	userOff := domainOff + len(domainBytes)
	workstationOff := userOff + len(userBytes)
	lmOff := workstationOff + len(workstationBytes)
	ntOff := lmOff + len(lmResp)
	keyOff := ntOff + len(ntResp)

	buf := bytes.NewBuffer(make([]byte, 0, keyOff+len(encryptedRandomSessionKey)))
	buf.WriteString("NTLMSSP\x00")
	_ = binary.Write(buf, binary.LittleEndian, uint32(3))
	writeSecBuf(buf, len(lmResp), lmOff)
	writeSecBuf(buf, len(ntResp), ntOff)
	writeSecBuf(buf, len(domainBytes), domainOff)
	writeSecBuf(buf, len(userBytes), userOff)
	writeSecBuf(buf, len(workstationBytes), workstationOff)
	writeSecBuf(buf, len(encryptedRandomSessionKey), keyOff)
	_ = binary.Write(buf, binary.LittleEndian, flags)
	buf.Write(domainBytes)
	buf.Write(userBytes)
	buf.Write(workstationBytes)
	buf.Write(lmResp)
	buf.Write(ntResp)
	buf.Write(encryptedRandomSessionKey)
	return buf.Bytes(), flags, exportedSessionKey
}

func writeSecBuf(buf *bytes.Buffer, n, off int) {
	_ = binary.Write(buf, binary.LittleEndian, mustUint16(n))
	_ = binary.Write(buf, binary.LittleEndian, mustUint16(n))
	_ = binary.Write(buf, binary.LittleEndian, mustUint32(off))
}

type ntlmSeal struct {
	signingKey []byte
	handle     *rc4Func
}

func (s *ntlmSeal) seal(flags, seqNum uint32, messageToSign, messageToEncrypt []byte) ([]byte, []byte) {
	sealed := s.handle.Apply(messageToEncrypt)
	sig := ntlmMessageSignature(flags, seqNum, messageToSign, s.signingKey, s.handle)
	return sealed, sig
}

func (s *ntlmSeal) sign(flags, seqNum uint32, messageToSign []byte) []byte {
	return ntlmMessageSignature(flags, seqNum, messageToSign, s.signingKey, s.handle)
}

func ntlmMessageSignature(flags, seqNum uint32, messageToSign, signingKey []byte, handle *rc4Func) []byte {
	if flags&ntlmSSPNegotiateExtendedSessionSecurity != 0 {
		checksum := hmacMD5(signingKey, append(le32(seqNum), messageToSign...))[:8]
		if flags&ntlmSSPNegotiateKeyExch != 0 {
			checksum = handle.Apply(checksum)
		}
		out := make([]byte, 16)
		binary.LittleEndian.PutUint32(out[0:4], 1)
		copy(out[4:12], checksum)
		binary.LittleEndian.PutUint32(out[12:16], seqNum)
		return out
	}
	return make([]byte, 16)
}

func le32(v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return b[:]
}
