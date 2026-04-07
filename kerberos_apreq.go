package wmi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

func wrapGSSKerberos(apReqBytes []byte) []byte {
	mechTypesInner := asn1Seq(oidIETFKRB5)
	mechTypes := asn1Tag(0, mechTypesInner)
	innerGSS := append(append([]byte(nil), oidMSKRB5...), []byte{0x01, 0x00}...)
	innerGSS = append(innerGSS, apReqBytes...)
	gssWrapper := append([]byte{0x60}, asn1Len(len(innerGSS))...)
	gssWrapper = append(gssWrapper, innerGSS...)
	mechToken := asn1Tag(2, asn1OctetString(gssWrapper))
	negBody := append(append([]byte(nil), mechTypes...), mechToken...)
	negInit := asn1Tag(0, asn1Seq(negBody))
	finalPayload := append(append([]byte(nil), oidSPNEGO...), negInit...)
	out := append([]byte{0x60}, asn1Len(len(finalPayload))...)
	return append(out, finalPayload...)
}

func buildAPReq(username, domain string, ticket, serviceSessionKey []byte, etype int) ([]byte, error) {
	now := time.Now().UTC()
	timestamp := now.Format("20060102150405Z")
	gssData := append([]byte{0x10, 0x00, 0x00, 0x00}, append(make([]byte, 16), []byte{0x3e, 0x10, 0x00, 0x00}...)...)
	cksumInner := append(asn1Tag(0, asn1Int(32771)), asn1Tag(1, asn1OctetString(gssData))...)
	cksumASN1 := asn1Tag(3, asn1Seq(cksumInner))

	uname := append(asn1Tag(0, asn1Int(1)), asn1Tag(1, asn1Seq(asn1GeneralString([]byte(username))))...)
	authBody := append(asn1Tag(0, asn1Int(5)), asn1Tag(1, asn1GeneralString([]byte(domain)))...)
	authBody = append(authBody, asn1Tag(2, asn1Seq(uname))...)
	authBody = append(authBody, cksumASN1...)
	authBody = append(authBody, asn1Tag(4, asn1Int(now.Nanosecond()/1000))...)
	authBody = append(authBody, asn1Tag(5, asn1GeneralizedTime([]byte(timestamp)))...)
	authBody = append(authBody, asn1Tag(7, []byte{0x02, 0x01, 0x00})...)
	authASN1 := asn1App(2, asn1Seq(authBody))

	var encAuth []byte
	var err error
	switch etype {
	case krbETypeAES128, krbETypeAES256:
		encAuth, err = encryptKerberosAESCTS(serviceSessionKey, 11, authASN1, nil)
	case krbETypeRC4:
		encAuth, err = encryptKerberosRC4(serviceSessionKey, 11, authASN1)
	default:
		return nil, fmt.Errorf("unsupported kerberos etype %d", etype)
	}
	if err != nil {
		return nil, err
	}
	encPart := asn1Tag(4, asn1Seq(append(asn1Tag(0, asn1Int(etype)), asn1Tag(2, asn1OctetString(encAuth))...)))
	body := append(asn1Tag(0, asn1Int(5)), asn1Tag(1, asn1Int(14))...)
	body = append(body, asn1Tag(2, []byte{0x03, 0x05, 0x00, 0x20, 0x00, 0x00, 0x00})...)
	body = append(body, asn1Tag(3, ticket)...)
	body = append(body, encPart...)
	return asn1App(14, asn1Seq(body)), nil
}

func getNegToken(serviceSessionKey []byte, seqNumber uint32, etype int) ([]byte, error) {
	now := time.Now().UTC()
	timestamp := now.Format("20060102150405Z")
	encBody := append(asn1Tag(0, asn1GeneralizedTime([]byte(timestamp))), asn1Tag(1, asn1Int(now.Nanosecond()/1000))...)
	encBody = append(encBody, asn1Tag(3, asn1Int(int(seqNumber)))...)
	plaintext := asn1App(27, asn1Seq(encBody))

	var encData []byte
	var err error
	switch etype {
	case krbETypeAES128, krbETypeAES256:
		encData, err = encryptKerberosAESCTS(serviceSessionKey, 12, plaintext, nil)
	case krbETypeRC4:
		encData, err = encryptKerberosRC4(serviceSessionKey, 12, plaintext)
	default:
		return nil, fmt.Errorf("unsupported kerberos etype %d", etype)
	}
	if err != nil {
		return nil, err
	}

	encPart := asn1Seq(append(asn1Tag(0, asn1Int(etype)), asn1Tag(2, asn1OctetString(encData))...))
	apRepBody := append(asn1Tag(0, asn1Int(5)), asn1Tag(1, asn1Int(15))...)
	apRepBody = append(apRepBody, asn1Tag(2, encPart)...)
	apRep := asn1App(15, asn1Seq(apRepBody))
	respToken := asn1Tag(2, asn1OctetString(apRep))
	return asn1Tag(1, asn1Seq(respToken)), nil
}

func getActiveKey(authBytes, serviceSessionKey []byte, etype int) ([]byte, uint32, error) {
	cipherBlob, err := extractActiveCipherBlob(authBytes, etype)
	if err != nil || len(cipherBlob) == 0 {
		return nil, 0, err
	}
	var decrypted []byte
	switch etype {
	case krbETypeRC4:
		decrypted, err = decryptKerberosRC4(serviceSessionKey, 12, cipherBlob)
	case krbETypeAES128, krbETypeAES256:
		decrypted, err = decryptKerberosAESCTS(serviceSessionKey, 12, cipherBlob)
	default:
		return nil, 0, fmt.Errorf("unsupported kerberos etype %d", etype)
	}
	if err != nil {
		return nil, 0, err
	}
	offset := 16
	if etype == krbETypeRC4 {
		offset = 0
	}
	if len(decrypted) < offset {
		return nil, 0, errors.New("short decrypted kerberos token")
	}
	return parseActiveKey(decrypted[offset:])
}

func extractActiveCipherBlob(authBytes []byte, etype int) ([]byte, error) {
	kerberosData := authBytes
	if len(authBytes) > 0 && authBytes[0] == 0xa1 {
		idxA2 := indexBytes(authBytes, []byte{0xa2})
		if idxA2 < 0 {
			return nil, nil
		}
		idx04 := indexByteRange(authBytes, idxA2, len(authBytes), 0x04)
		if idx04 < 0 {
			return nil, nil
		}
		length, ll, err := getASN1Len(authBytes, idx04+1)
		if err != nil {
			return nil, err
		}
		start := idx04 + 1 + ll
		end := start + length
		if end > len(authBytes) {
			return nil, errors.New("short kerberos auth data")
		}
		kerberosData = authBytes[start:end]
	}
	marker := asn1Int(etype)
	etypeIdx := indexBytes(kerberosData, marker)
	if etypeIdx < 0 {
		return nil, nil
	}
	idx04 := indexByteRange(kerberosData, etypeIdx, len(kerberosData), 0x04)
	if idx04 < 0 {
		return nil, nil
	}
	length, ll, err := getASN1Len(kerberosData, idx04+1)
	if err != nil {
		return nil, err
	}
	start := idx04 + 1 + ll
	end := start + length
	if end > len(kerberosData) {
		return nil, errors.New("short kerberos cipher blob")
	}
	return append([]byte(nil), kerberosData[start:end]...), nil
}

func parseActiveKey(data []byte) ([]byte, uint32, error) {
	var activeKey []byte
	var seqNumber uint32

	walk := data
	if len(walk) > 0 && walk[0] == 0x7b {
		root, err := parseASN1(walk, 0)
		if err != nil {
			return nil, 0, err
		}
		seq, err := parseASN1(root.content, 0)
		if err != nil {
			return nil, 0, err
		}
		walk = seq.content
	}

	children, err := parseASN1Children(walk)
	if err != nil {
		return nil, 0, err
	}
	for _, child := range children {
		switch child.tag {
		case 0xa2:
			seq, err := parseASN1(child.content, 0)
			if err != nil {
				return nil, 0, err
			}
			keyField, ok, err := findASN1Child(seq.content, 0xa1)
			if err != nil {
				return nil, 0, err
			}
			if ok {
				octets, err := parseASN1(keyField.content, 0)
				if err != nil {
					return nil, 0, err
				}
				activeKey = append([]byte(nil), octets.content...)
			}
		case 0xa3:
			val, err := asn1IntegerValue(child.content)
			if err != nil {
				return nil, 0, err
			}
			seqNumber, err = checkedUint32(val)
			if err != nil {
				return nil, 0, err
			}
		}
	}
	return activeKey, seqNumber, nil
}

func seqBytes(seqNum uint32, direction byte) []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint32(out[:4], seqNum)
	for i := 4; i < 8; i++ {
		out[i] = direction
	}
	return out
}
