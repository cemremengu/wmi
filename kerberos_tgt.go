package wmi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

var kerberosErrors = map[int]string{
	6:  "KDC_ERR_C_PRINCIPAL_UNKNOWN",
	7:  "KDC_ERR_S_PRINCIPAL_UNKNOWN",
	14: "KDC_ERR_ETYPE_NOSUPP",
	24: "KDC_ERR_PREAUTH_FAILED",
	25: "KDC_ERR_PREAUTH_REQUIRED",
	37: "KRB_AP_ERR_SKEW",
	60: "KRB_ERR_GENERIC",
}

func buildASReq(username, domain string) []byte {
	domain = strings.ToUpper(domain)
	pacReq := asn1Seq(asn1Tag(0, []byte{0x01, 0x01, 0xff}))
	padataElement := asn1Seq(append(asn1Tag(1, asn1Int(128)), asn1Tag(2, asn1OctetString(pacReq))...))
	padataSeq := asn1Seq(padataElement)

	snameComponents := append(asn1GeneralString([]byte("krbtgt")), asn1GeneralString([]byte(domain))...)
	sname := append(asn1Tag(0, asn1Int(1)), asn1Tag(1, asn1Seq(snameComponents))...)

	cname := append(asn1Tag(0, asn1Int(1)), asn1Tag(1, asn1Seq(asn1GeneralString([]byte(username))))...)

	now := time.Now().UTC()
	fromTime := now.Add(-5 * time.Minute).Format("20060102150405Z")
	till := now.Add(10 * time.Hour).Format("20060102150405Z")
	rtime := now.Add(24 * time.Hour).Format("20060102150405Z")
	nonce := int(binary.BigEndian.Uint32(randBytes(4)) & 0x7fffffff)

	reqBody := append(asn1Tag(0, []byte{0x03, 0x05, 0x00, 0x50, 0x80, 0x00, 0x00}), asn1Tag(1, asn1Seq(cname))...)
	reqBody = append(reqBody, asn1Tag(2, asn1GeneralString([]byte(domain)))...)
	reqBody = append(reqBody, asn1Tag(3, asn1Seq(sname))...)
	reqBody = append(reqBody, asn1Tag(4, asn1GeneralizedTime([]byte(fromTime)))...)
	reqBody = append(reqBody, asn1Tag(5, asn1GeneralizedTime([]byte(till)))...)
	reqBody = append(reqBody, asn1Tag(6, asn1GeneralizedTime([]byte(rtime)))...)
	reqBody = append(reqBody, asn1Tag(7, asn1Int(nonce))...)
	reqBody = append(reqBody, asn1Tag(8, asn1Seq(asn1Int(krbETypeAES256)))...)

	content := append(asn1Tag(1, asn1Int(5)), asn1Tag(2, asn1Int(10))...)
	content = append(content, asn1Tag(3, padataSeq)...)
	content = append(content, asn1Tag(4, asn1Seq(reqBody))...)
	return asn1App(10, asn1Seq(content))
}

func buildFullASReq(username, domain string, baseKey []byte, etype int) ([]byte, error) {
	now := time.Now().UTC()
	ts := now.Format("20060102150405Z")
	plain := asn1Seq(append(asn1Tag(0, asn1GeneralizedTime([]byte(ts))), asn1Tag(1, asn1Int(now.Nanosecond()/1000))...))
	encTS, err := encryptKerberosAESCTS(baseKey, 1, plain, nil)
	if err != nil {
		return nil, err
	}

	encData := asn1Seq(append(asn1Tag(0, asn1Int(etype)), asn1Tag(2, asn1OctetString(encTS))...))
	paTS := asn1Seq(append(asn1Tag(1, asn1Int(2)), asn1Tag(2, asn1OctetString(encData))...))
	paPAC := asn1Seq(
		append(asn1Tag(1, asn1Int(128)), asn1Tag(2, asn1OctetString(asn1Seq(asn1Tag(0, []byte{0x01, 0x01, 0xff}))))...),
	)

	domain = strings.ToUpper(domain)
	nonce := int(binary.BigEndian.Uint32(randBytes(4)) & 0x7fffffff)
	till := now.Add(24 * time.Hour).Format("20060102150405Z")
	cname := append(asn1Tag(0, asn1Int(1)), asn1Tag(1, asn1Seq(asn1GeneralString([]byte(username))))...)
	snameParts := append(asn1GeneralString([]byte("krbtgt")), asn1GeneralString([]byte(domain))...)
	sname := append(asn1Tag(0, asn1Int(1)), asn1Tag(1, asn1Seq(snameParts))...)

	reqBody := append(asn1Tag(0, []byte{0x03, 0x05, 0x00, 0x50, 0x80, 0x00, 0x00}), asn1Tag(1, asn1Seq(cname))...)
	reqBody = append(reqBody, asn1Tag(2, asn1GeneralString([]byte(domain)))...)
	reqBody = append(reqBody, asn1Tag(3, asn1Seq(sname))...)
	reqBody = append(reqBody, asn1Tag(5, asn1GeneralizedTime([]byte(till)))...)
	reqBody = append(reqBody, asn1Tag(6, asn1GeneralizedTime([]byte(till)))...)
	reqBody = append(reqBody, asn1Tag(7, asn1Int(nonce))...)
	reqBody = append(reqBody, asn1Tag(8, asn1Seq(asn1Int(etype)))...)

	padata := asn1Seq(append(paTS, paPAC...))
	content := append(asn1Tag(1, asn1Int(5)), asn1Tag(2, asn1Int(10))...)
	content = append(content, asn1Tag(3, padata)...)
	content = append(content, asn1Tag(4, asn1Seq(reqBody))...)
	return asn1App(10, asn1Seq(content)), nil
}

func kerberosErrorCode(data []byte) (int, bool, error) {
	root, err := parseASN1(data, 0)
	if err != nil {
		return 0, false, err
	}
	if root.tag != 0x7e {
		return 0, false, nil
	}
	seq, err := parseASN1(root.content, 0)
	if err != nil {
		return 0, true, err
	}
	codeField, ok, err := findASN1Child(seq.content, 0xa6)
	if err != nil {
		return 0, true, err
	}
	if !ok {
		return 0, true, errors.New("kerberos error-code field not found")
	}
	code, err := asn1IntegerValue(codeField.content)
	if err != nil {
		return 0, true, err
	}
	return code, true, nil
}

func parseKerberosError(data []byte) error {
	code, isErr, err := kerberosErrorCode(data)
	if err != nil || !isErr {
		return err
	}
	msg := kerberosErrors[code]
	if msg == "" {
		msg = fmt.Sprintf("KERBEROS_ERROR_%d", code)
	}
	return errors.New(msg)
}

func extractSaltAndEtype(errorData []byte) (string, int, error) {
	if len(errorData) == 0 || errorData[0] != 0x7e {
		return "", 0, errors.New("invalid KRB-ERROR packet")
	}
	eDataIdx := strings.Index(string(errorData), string([]byte{0xac}))
	if eDataIdx < 0 {
		return "", 0, errors.New("kerberos e-data not found")
	}
	etype := krbETypeAES256
	marker := []byte{0x02, 0x01, 0x12}
	markerIdx := indexBytes(errorData[eDataIdx:], marker)
	if markerIdx < 0 {
		etype = krbETypeAES128
		marker = []byte{0x02, 0x01, 0x11}
		markerIdx = indexBytes(errorData[eDataIdx:], marker)
		if markerIdx < 0 {
			return "", 0, errors.New("no AES etype found in kerberos error")
		}
	}
	markerIdx += eDataIdx
	saltTagIdx := indexBytes(errorData[markerIdx:], []byte{0xa1})
	if saltTagIdx < 0 {
		return "", 0, errors.New("salt tag not found")
	}
	saltTagIdx += markerIdx
	saltStart := -1
	for _, tag := range []byte{0x1b, 0x04, 0x1d} {
		if pos := indexByteRange(errorData, saltTagIdx, saltTagIdx+15, tag); pos >= 0 {
			saltStart = pos
			break
		}
	}
	if saltStart < 0 {
		return "", 0, errors.New("salt payload not found")
	}
	saltLen, ll, err := getASN1Len(errorData, saltStart+1)
	if err != nil {
		return "", 0, err
	}
	start := saltStart + 1 + ll
	end := start + saltLen
	if end > len(errorData) || start == end {
		return "", 0, errors.New("invalid salt payload")
	}
	return string(errorData[start:end]), etype, nil
}

func getTGT(ctx context.Context, username, password, domain, kdcHost string, kdcPort int) ([]byte, []byte, error) {
	resp, err := sendKerberosPacket(ctx, buildASReq(username, domain), kdcHost, kdcPort)
	if err != nil {
		return nil, nil, err
	}
	code, isErr, err := kerberosErrorCode(resp)
	if err != nil {
		return nil, nil, err
	}
	if !isErr || code != krbErrPreauthRequired {
		if isErr {
			return nil, nil, parseKerberosError(resp)
		}
		return nil, nil, errors.New("expected KRB-ERROR preauth challenge")
	}
	salt, etype, err := extractSaltAndEtype(resp)
	if err != nil {
		return nil, nil, err
	}
	keyLen := 32
	if etype == krbETypeAES128 {
		keyLen = 16
	}
	baseKey := aesStringToKey(usernamePassword(password), salt, keyLen)
	fullReq, err := buildFullASReq(username, domain, baseKey, etype)
	if err != nil {
		return nil, nil, err
	}
	asRepBytes, err := sendKerberosPacket(ctx, fullReq, kdcHost, kdcPort)
	if err != nil {
		return nil, nil, err
	}
	if err := parseKerberosError(asRepBytes); err != nil {
		return nil, nil, err
	}
	return asRepBytes, baseKey, nil
}

func usernamePassword(password string) string {
	return password
}

func indexBytes(data, needle []byte) int {
	for i := 0; i+len(needle) <= len(data); i++ {
		match := true
		for j := range needle {
			if data[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func indexByteRange(data []byte, start, end int, needle byte) int {
	if start < 0 {
		start = 0
	}
	if end > len(data) {
		end = len(data)
	}
	for i := start; i < end; i++ {
		if data[i] == needle {
			return i
		}
	}
	return -1
}
