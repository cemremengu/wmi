package wmi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

func replySequenceContent(data []byte) ([]byte, error) {
	root, err := parseASN1(data, 0)
	if err != nil {
		return nil, err
	}
	seq, err := parseASN1(root.content, 0)
	if err != nil {
		return nil, err
	}
	if seq.tag != 0x30 {
		return nil, fmt.Errorf("expected kerberos sequence, got %#x", seq.tag)
	}
	return seq.content, nil
}

func replyField(data []byte, field byte) (asn1Value, error) {
	content, err := replySequenceContent(data)
	if err != nil {
		return asn1Value{}, err
	}
	elem, ok, err := findASN1Child(content, 0xa0+field)
	if err != nil {
		return asn1Value{}, err
	}
	if !ok {
		return asn1Value{}, fmt.Errorf("kerberos field [%d] not found", field)
	}
	return elem, nil
}

func encryptedDataCipher(field asn1Value) ([]byte, error) {
	seq, err := parseASN1(field.content, 0)
	if err != nil {
		return nil, err
	}
	cipherField, ok, err := findASN1Child(seq.content, 0xa2)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("cipher field not found")
	}
	octets, err := parseASN1(cipherField.content, 0)
	if err != nil {
		return nil, err
	}
	if octets.tag != 0x04 {
		return nil, fmt.Errorf("unexpected cipher tag %#x", octets.tag)
	}
	return append([]byte(nil), octets.content...), nil
}

func getSessionKey(asRepBytes, baseKey []byte) ([]byte, error) {
	encPart, err := replyField(asRepBytes, 6)
	if err != nil {
		return nil, err
	}
	cipherBlob, err := encryptedDataCipher(encPart)
	if err != nil {
		return nil, err
	}
	decrypted, err := decryptKerberosAESCTS(baseKey, 3, cipherBlob)
	if err != nil {
		return nil, err
	}
	return readSessionKey(decrypted)
}

func extractTicket(data []byte) ([]byte, error) {
	field, err := replyField(data, 5)
	if err != nil {
		return nil, err
	}
	ticket, err := parseASN1(field.content, 0)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), ticket.full...), nil
}

func buildTGSReq(
	username, domain string,
	sessionKey, ticketBytes []byte,
	targetService [2]string,
	etype int,
) ([]byte, time.Time, error) {
	now := time.Now().UTC()
	till := now.Add(8 * time.Hour)
	tsStr := now.Format("20060102150405Z")
	tillStr := till.Format("20060102150405Z")
	cname := append(asn1Tag(0, asn1Int(1)), asn1Tag(1, asn1Seq(asn1GeneralString([]byte(username))))...)
	authBody := append(asn1Tag(0, asn1Int(5)), asn1Tag(1, asn1GeneralString([]byte(strings.ToUpper(domain))))...)
	authBody = append(authBody, asn1Tag(2, asn1Seq(cname))...)
	authBody = append(authBody, asn1Tag(4, asn1Int(now.Nanosecond()/1000))...)
	authBody = append(authBody, asn1Tag(5, asn1GeneralizedTime([]byte(tsStr)))...)
	authPlain := asn1App(2, asn1Seq(authBody))

	finalCipher, err := encryptKerberosAESCTS(sessionKey, 7, authPlain, nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	authEncSeq := asn1Seq(append(asn1Tag(0, asn1Int(etype)), asn1Tag(2, asn1OctetString(finalCipher))...))
	apReqBody := append(asn1Tag(0, asn1Int(5)), asn1Tag(1, asn1Int(14))...)
	apReqBody = append(apReqBody, asn1Tag(2, []byte{0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00})...)
	apReqBody = append(apReqBody, asn1Tag(3, ticketBytes)...)
	apReqBody = append(apReqBody, asn1Tag(4, authEncSeq)...)
	encodedAPReq := asn1App(14, asn1Seq(apReqBody))

	padataItem := asn1Seq(append(asn1Tag(1, asn1Int(1)), asn1Tag(2, asn1OctetString(encodedAPReq))...))
	serviceParts := append(asn1GeneralString([]byte(targetService[0])), asn1GeneralString([]byte(targetService[1]))...)
	sname := append(asn1Tag(0, asn1Int(2)), asn1Tag(1, asn1Seq(serviceParts))...)
	nonce := int(binary.BigEndian.Uint32(randBytes(4)) & 0x7fffffff)

	etypes := append(asn1Int(krbETypeRC4), append(asn1Int(krbETypeAES128), asn1Int(krbETypeAES256)...)...)
	reqBody := append(
		asn1Tag(0, []byte{0x03, 0x05, 0x00, 0x40, 0x81, 0x00, 0x10}),
		asn1Tag(2, asn1GeneralString([]byte(strings.ToUpper(domain))))...)
	reqBody = append(reqBody, asn1Tag(3, asn1Seq(sname))...)
	reqBody = append(reqBody, asn1Tag(5, asn1GeneralizedTime([]byte(tillStr)))...)
	reqBody = append(reqBody, asn1Tag(7, asn1Int(nonce))...)
	reqBody = append(reqBody, asn1Tag(8, asn1Seq(etypes))...)

	content := append(asn1Tag(1, asn1Int(5)), asn1Tag(2, asn1Int(12))...)
	content = append(content, asn1Tag(3, asn1Seq(padataItem))...)
	content = append(content, asn1Tag(4, asn1Seq(reqBody))...)
	return asn1App(12, asn1Seq(content)), till, nil
}

func getServiceKey(respBytes, sessionKey []byte) ([]byte, []byte, int, error) {
	encPart, err := replyField(respBytes, 6)
	if err != nil {
		return nil, nil, 0, err
	}
	cipherBlob, err := encryptedDataCipher(encPart)
	if err != nil {
		return nil, nil, 0, err
	}
	decrypted, err := decryptKerberosAESCTS(sessionKey, 8, cipherBlob)
	if err != nil {
		return nil, nil, 0, err
	}
	serviceEType, serviceKey, err := readEncryptionKey(decrypted)
	if err != nil {
		return nil, nil, 0, err
	}
	ticket, err := extractTicket(respBytes)
	if err != nil {
		return nil, nil, 0, err
	}
	return ticket, serviceKey, serviceEType, nil
}

func getTGS(
	ctx context.Context,
	username, domain, host string,
	asRepBytes, baseKey []byte,
	kdcHost string,
	kdcPort int,
) ([]byte, []byte, int, time.Time, error) {
	tgsSessionKey, err := getSessionKey(asRepBytes, baseKey)
	if err != nil {
		return nil, nil, 0, time.Time{}, err
	}
	tgsTicket, err := extractTicket(asRepBytes)
	if err != nil {
		return nil, nil, 0, time.Time{}, err
	}
	etype := krbETypeAES256
	if len(tgsSessionKey) == 16 {
		etype = krbETypeAES128
	}
	tgsReq, till, err := buildTGSReq(username, domain, tgsSessionKey, tgsTicket, [2]string{"host", host}, etype)
	if err != nil {
		return nil, nil, 0, time.Time{}, err
	}
	resp, err := sendKerberosPacket(ctx, tgsReq, kdcHost, kdcPort)
	if err != nil {
		return nil, nil, 0, time.Time{}, err
	}
	if err := parseKerberosError(resp); err != nil {
		return nil, nil, 0, time.Time{}, err
	}
	ticket, serviceKey, serviceEType, err := getServiceKey(resp, tgsSessionKey)
	if err != nil {
		return nil, nil, 0, time.Time{}, err
	}
	return ticket, serviceKey, serviceEType, till, nil
}
