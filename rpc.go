package wmi

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type dcomState struct {
	maxXmitFrag uint16
	callID      uint32
	seqNum      uint32
}

func newDCOMState() *dcomState {
	return &dcomState{callID: 1}
}

func (d *dcomState) nextCallID() uint32 {
	id := d.callID
	d.callID++
	return id
}

func (d *dcomState) nextSeqNum() uint32 {
	seq := d.seqNum
	d.seqNum++
	return seq
}

type rpcCommon struct {
	rpcVers      byte
	rpcVersMinor byte
	ptype        byte
	pfcFlags     byte
	packedDrep   uint32
	fragLength   uint16
	authLength   uint16
	callID       uint32
	pduData      []byte
	authVerifier []byte
}

func newRPCCommon(ptype byte) *rpcCommon {
	return &rpcCommon{
		rpcVers:      5,
		rpcVersMinor: 0,
		ptype:        ptype,
		pfcFlags:     pfcFirstFrag | pfcLastFrag,
		packedDrep:   0x10,
		fragLength:   16,
		callID:       1,
	}
}

func parseRPCCommon(data []byte) (*rpcCommon, error) {
	if len(data) < 16 {
		return nil, errors.New("short RPC header")
	}
	return &rpcCommon{
		rpcVers:      data[0],
		rpcVersMinor: data[1],
		ptype:        data[2],
		pfcFlags:     data[3],
		packedDrep:   binary.LittleEndian.Uint32(data[4:8]),
		fragLength:   binary.LittleEndian.Uint16(data[8:10]),
		authLength:   binary.LittleEndian.Uint16(data[10:12]),
		callID:       binary.LittleEndian.Uint32(data[12:16]),
	}, nil
}

func (r *rpcCommon) setPDUData(pdu []byte) {
	r.fragLength -= mustUint16(len(r.pduData))
	r.pduData = append(r.pduData[:0], pdu...)
	r.fragLength += mustUint16(len(r.pduData))
}

func (r *rpcCommon) setAuthVerifier(auth []byte, authLength uint16) {
	r.authVerifier = append(r.authVerifier[:0], auth...)
	r.authLength = authLength
	r.fragLength += mustUint16(len(auth))
}

func (r *rpcCommon) setAuthData(authData []byte) {
	prefixLen := len(r.authVerifier) - int(r.authLength)
	r.authVerifier = append(append([]byte(nil), r.authVerifier[:prefixLen]...), authData...)
	r.fragLength += mustUint16(len(authData)) - r.authLength
	r.authLength = mustUint16(len(authData))
}

func (r *rpcCommon) bytes() []byte {
	out := make([]byte, 16+len(r.pduData)+len(r.authVerifier))
	out[0] = r.rpcVers
	out[1] = r.rpcVersMinor
	out[2] = r.ptype
	out[3] = r.pfcFlags
	binary.LittleEndian.PutUint32(out[4:8], r.packedDrep)
	binary.LittleEndian.PutUint16(out[8:10], r.fragLength)
	binary.LittleEndian.PutUint16(out[10:12], r.authLength)
	binary.LittleEndian.PutUint32(out[12:16], r.callID)
	copy(out[16:], r.pduData)
	copy(out[16+len(r.pduData):], r.authVerifier)
	return out
}

type rpcAuthVerifier struct {
	authType      byte
	authLevel     byte
	authPadLength byte
	authContextID uint32
	authValue     []byte
}

func makeRPCAuthVerifier(
	authType, authLevel byte,
	authPadLength byte,
	authContextID uint32,
	authValue []byte,
) ([]byte, uint16) {
	padding := bytes.Repeat([]byte{0xff}, int(authPadLength))
	buf := bytes.NewBuffer(make([]byte, 0, len(padding)+8+len(authValue)))
	buf.Write(padding)
	buf.WriteByte(authType)
	buf.WriteByte(authLevel)
	buf.WriteByte(authPadLength)
	buf.WriteByte(0)
	_ = binary.Write(buf, binary.LittleEndian, authContextID)
	buf.Write(authValue)
	return buf.Bytes(), mustUint16(len(authValue))
}

func parseRPCAuthVerifier(data []byte, authLength uint16, offset int) (*rpcAuthVerifier, error) {
	if offset >= len(data) {
		return nil, errors.New("short auth verifier")
	}
	parseAt := func(start int) (*rpcAuthVerifier, bool) {
		if start+8 > len(data) {
			return nil, false
		}
		valueStart := start + 8
		if valueStart+int(authLength) > len(data) {
			return nil, false
		}
		authType := data[start]
		authLevel := data[start+1]
		authPadLength := data[start+2]
		if data[start+3] != 0 {
			return nil, false
		}
		switch authType {
		case rpcCAuthNWinNT, rpcCAuthNGSSNegotiate:
		default:
			return nil, false
		}
		if authLevel > rpcCAuthNLevelPktPrivacy {
			return nil, false
		}
		return &rpcAuthVerifier{
			authType:      authType,
			authLevel:     authLevel,
			authPadLength: authPadLength,
			authContextID: binary.LittleEndian.Uint32(data[start+4 : start+8]),
			authValue:     append([]byte(nil), data[valueStart:valueStart+int(authLength)]...),
		}, true
	}

	if auth, ok := parseAt(offset); ok {
		return auth, nil
	}
	for pad := 1; pad <= 3; pad++ {
		start := offset + pad
		auth, ok := parseAt(start)
		if !ok || auth.authPadLength != byte(pad) {
			continue
		}
		return auth, nil
	}
	return nil, errors.New("invalid auth verifier layout")
}

type rpcContElem struct {
	pContID          uint16
	abstractSyntax   []byte
	transferSyntaxes [][]byte
}

func (r *rpcContElem) bytes() []byte {
	buf := bytes.NewBuffer(make([]byte, 0, 4+len(r.abstractSyntax)+len(r.transferSyntaxes)*20))
	_ = binary.Write(buf, binary.LittleEndian, r.pContID)
	buf.WriteByte(mustByte(len(r.transferSyntaxes)))
	buf.WriteByte(0)
	buf.Write(r.abstractSyntax)
	for _, ts := range r.transferSyntaxes {
		buf.Write(ts)
	}
	return buf.Bytes()
}

type rpcBind struct {
	*rpcCommon
	elems []rpcContElem
}

func newRPCBind() *rpcBind {
	return &rpcBind{rpcCommon: newRPCCommon(msrpcBind)}
}

func (r *rpcBind) addContElem(elem rpcContElem) {
	elem.pContID = mustUint16(len(r.elems))
	r.elems = append(r.elems, elem)
}

func (r *rpcBind) freeze() int {
	buf := bytes.NewBuffer(make([]byte, 0, 24+len(r.elems)*24))
	_ = binary.Write(buf, binary.LittleEndian, uint16(0x10b8))
	_ = binary.Write(buf, binary.LittleEndian, uint16(0x10b8))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	buf.WriteByte(mustByte(len(r.elems)))
	buf.WriteByte(0)
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))
	for _, elem := range r.elems {
		buf.Write(elem.bytes())
	}
	r.setPDUData(buf.Bytes())
	return len(r.pduData)
}

func newRPCAlterContext(
	iid []byte,
	callID uint32,
	authType, authLevel byte,
	contextID uint32,
	authValue []byte,
) []byte {
	body := bytes.NewBuffer(make([]byte, 0, 100))
	body.Write([]byte{0x00, 0x00, 0x00, 0x00})
	body.Write([]byte{0x01, 0x00, 0x00, 0x00})
	body.Write([]byte{0x00, 0x00})
	body.Write([]byte{0x01, 0x00})
	body.Write(iid)
	body.Write(ndrTransferSyntaxIdentifier)
	body.Write([]byte{0x00, 0x00, 0x01, 0x00})
	body.Write(iid)
	body.Write(ndrTransferSyntaxIdentifier)

	common := newRPCCommon(msrpcAlterCtx)
	common.callID = callID
	common.setPDUData(append([]byte{0xb8, 0x10, 0xb8, 0x10}, body.Bytes()...))
	auth, authLen := makeRPCAuthVerifier(authType, authLevel, 0, contextID, authValue)
	common.setAuthVerifier(auth, authLen)
	return common.bytes()
}

type rpcRequest struct {
	*rpcCommon
	opnum   uint16
	uuidStr string
	appData []byte
}

func newRPCRequest(opnum uint16, uuidStr string) *rpcRequest {
	r := &rpcRequest{rpcCommon: newRPCCommon(msrpcRequest), opnum: opnum, uuidStr: uuidStr}
	if uuidStr != "" {
		r.pfcFlags |= pfcObjectUUID
	}
	return r
}

func (r *rpcRequest) setAppData(data []byte) {
	r.appData = append(r.appData[:0], data...)
	r.setPDUData(data)
}

func (r *rpcRequest) sealData(proto *protocol, ctxID uint16) ([]byte, error) {
	if proto.authType == rpcCAuthNGSSNegotiate {
		return r.wrapKerberos(proto, ctxID)
	}
	authPad := mustByte(pad4(len(r.appData)))
	messageToEncrypt := append([]byte(nil), r.appData...)
	pdu := bytes.NewBuffer(make([]byte, 0, 8+len(messageToEncrypt)+16))
	_ = binary.Write(pdu, binary.LittleEndian, mustUint32(len(messageToEncrypt)))
	_ = binary.Write(pdu, binary.LittleEndian, ctxID)
	_ = binary.Write(pdu, binary.LittleEndian, r.opnum)
	if r.pfcFlags&pfcObjectUUID != 0 {
		ub, err := uuidToBin(r.uuidStr)
		if err != nil {
			return nil, err
		}
		pdu.Write(ub)
	}
	pdu.Write(messageToEncrypt)
	r.setPDUData(pdu.Bytes())

	auth, authLen := makeRPCAuthVerifier(
		proto.authType,
		proto.authLevel,
		authPad,
		proto.contextID,
		bytes.Repeat([]byte(" "), 16),
	)
	r.callID = proto.dcom.nextCallID()
	r.setAuthVerifier(auth, authLen)

	messageToSign := r.bytes()[:len(r.bytes())-16]
	seq := proto.dcom.nextSeqNum()
	debugf(
		"rpc seal request call_id=%d seq=%d opnum=%d ctx_id=%d uuid=%s app_len=%d auth_pad=%d",
		r.callID,
		seq,
		r.opnum,
		ctxID,
		r.uuidStr,
		len(messageToEncrypt),
		authPad,
	)
	sealed, sig := proto.clientSeal.seal(proto.flags, seq, messageToSign, messageToEncrypt)
	pdu.Reset()
	_ = binary.Write(pdu, binary.LittleEndian, mustUint32(len(messageToEncrypt)))
	_ = binary.Write(pdu, binary.LittleEndian, ctxID)
	_ = binary.Write(pdu, binary.LittleEndian, r.opnum)
	if r.pfcFlags&pfcObjectUUID != 0 {
		ub, _ := uuidToBin(r.uuidStr)
		pdu.Write(ub)
	}
	pdu.Write(sealed)
	r.setPDUData(pdu.Bytes())
	r.setAuthData(sig)
	debugf("rpc seal request ready call_id=%d sealed_len=%d sig_len=%d", r.callID, len(sealed), len(sig))
	return r.bytes(), nil
}

func (r *rpcRequest) signData(proto *protocol) ([]byte, error) {
	if proto.authType == rpcCAuthNGSSNegotiate && proto.authLevel == rpcCAuthNLevelPktPrivacy {
		return r.wrapKerberos(proto, 0)
	}
	authPad := mustByte(pad4(len(r.appData)))
	pdu := bytes.NewBuffer(make([]byte, 0, 8+len(r.appData)+16))
	_ = binary.Write(pdu, binary.LittleEndian, mustUint32(len(r.appData)))
	_ = binary.Write(pdu, binary.LittleEndian, uint16(0))
	_ = binary.Write(pdu, binary.LittleEndian, r.opnum)
	if r.pfcFlags&pfcObjectUUID != 0 {
		ub, err := uuidToBin(r.uuidStr)
		if err != nil {
			return nil, err
		}
		pdu.Write(ub)
	}
	pdu.Write(r.appData)
	r.setPDUData(pdu.Bytes())

	auth, authLen := makeRPCAuthVerifier(
		proto.authType,
		proto.authLevel,
		authPad,
		proto.contextID,
		bytes.Repeat([]byte(" "), 16),
	)
	r.callID = proto.dcom.nextCallID()
	r.setAuthVerifier(auth, authLen)

	seq := proto.dcom.nextSeqNum()
	debugf(
		"rpc sign request call_id=%d seq=%d opnum=%d uuid=%s app_len=%d auth_pad=%d auth_type=%d auth_level=%d",
		r.callID,
		seq,
		r.opnum,
		r.uuidStr,
		len(r.appData),
		authPad,
		proto.authType,
		proto.authLevel,
	)
	switch {
	case proto.authLevel == rpcCAuthNLevelPktIntegrity && proto.authType == rpcCAuthNWinNT:
		sig := proto.clientSign.sign(proto.flags, seq, r.bytes()[:len(r.bytes())-16])
		r.setAuthData(sig)
		debugf("rpc sign request ready call_id=%d sig_len=%d", r.callID, len(sig))
	default:
		return nil, fmt.Errorf(
			"unsupported sign combination auth_level=%d auth_type=%d",
			proto.authLevel,
			proto.authType,
		)
	}
	return r.bytes(), nil
}

func (r *rpcRequest) wrapKerberos(proto *protocol, ctxID uint16) ([]byte, error) {
	if proto.krbWrap == nil {
		return nil, errors.New("kerberos wrap function is not configured")
	}
	authPad := mustByte(pad4(len(r.appData)))
	pdu := bytes.NewBuffer(make([]byte, 0, 8+len(r.appData)))
	_ = binary.Write(pdu, binary.LittleEndian, mustUint32(len(r.appData)))
	_ = binary.Write(pdu, binary.LittleEndian, ctxID)
	_ = binary.Write(pdu, binary.LittleEndian, r.opnum)
	if r.pfcFlags&pfcObjectUUID != 0 {
		ub, err := uuidToBin(r.uuidStr)
		if err != nil {
			return nil, err
		}
		pdu.Write(ub)
	}
	seq := proto.dcom.nextSeqNum()
	debugf(
		"rpc kerberos wrap request seq=%d opnum=%d ctx_id=%d uuid=%s app_len=%d",
		seq,
		r.opnum,
		ctxID,
		r.uuidStr,
		len(r.appData),
	)
	sealed, sig, err := proto.krbWrap(seq, r.appData)
	if err != nil {
		return nil, err
	}
	pdu.Write(sealed)
	r.setPDUData(pdu.Bytes())
	auth, authLen := makeRPCAuthVerifier(proto.authType, proto.authLevel, authPad, proto.contextID, sig)
	r.callID = proto.dcom.nextCallID()
	r.setAuthVerifier(auth, authLen)
	debugf("rpc kerberos wrap ready call_id=%d sealed_len=%d auth_len=%d", r.callID, len(sealed), authLen)
	return r.bytes(), nil
}

type rpcBindAck struct {
	secAddr []byte
	auth    *rpcAuthVerifier
}

type rpcAlterCtxR struct {
	auth *rpcAuthVerifier
}

func parseRPCBindAck(d *dcomState, common *rpcCommon, data []byte) (*rpcBindAck, error) {
	if len(data) < 26 {
		return nil, errors.New("short bind ack")
	}
	maxXmitFrag := binary.LittleEndian.Uint16(data[16:18])
	d.maxXmitFrag = maxXmitFrag
	secAddrLen := int(binary.LittleEndian.Uint16(data[24:26]))
	offset := 26
	if offset+secAddrLen > len(data) {
		return nil, errors.New("short bind ack sec addr")
	}
	ack := &rpcBindAck{secAddr: append([]byte(nil), data[offset:offset+secAddrLen]...)}
	offset += secAddrLen
	offset += pad4(offset)
	if offset+4 > len(data) {
		return ack, nil
	}
	nResults := int(data[offset])
	offset += 4
	offset += nResults * 24
	offset += pad4(offset)
	if common.authLength > 0 {
		auth, err := parseRPCAuthVerifier(data, common.authLength, offset)
		if err != nil {
			return nil, err
		}
		ack.auth = auth
	}
	return ack, nil
}

func parseRPCBindNak(data []byte) error {
	if len(data) < 20 {
		return errors.New("short bind nak")
	}
	reason := binary.LittleEndian.Uint16(data[16:18])
	status := uint32(binary.LittleEndian.Uint16(data[18:20]))
	if len(data) >= 24 {
		altReason := binary.LittleEndian.Uint16(data[18:20])
		altStatus := binary.LittleEndian.Uint32(data[20:24])
		if reason > rpcBindNakReasonInvalidAuthInstance && altReason <= rpcBindNakReasonInvalidAuthInstance {
			reason = altReason
			status = altStatus
		}
	}
	return bindNakError(reason, status)
}

func parseRPCAlterCtxR(d *dcomState, common *rpcCommon, data []byte) (*rpcAlterCtxR, error) {
	if len(data) < 28 {
		return nil, errors.New("short alter context response")
	}
	d.maxXmitFrag = binary.LittleEndian.Uint16(data[16:18])
	offset := 24
	offset += pad4(offset)
	if offset+4 > len(data) {
		return &rpcAlterCtxR{}, nil
	}
	nResults := int(data[offset])
	offset += 4
	offset += nResults * 24
	offset += pad4(offset)
	resp := &rpcAlterCtxR{}
	if common.authLength > 0 {
		auth, err := parseRPCAuthVerifier(data, common.authLength, offset)
		if err != nil {
			return nil, err
		}
		resp.auth = auth
	}
	return resp, nil
}

type rpcResponseFrag struct {
	common *rpcCommon
	body   []byte
}

type rpcReply struct {
	ptype     byte
	bindAck   *rpcBindAck
	alterCtxR *rpcAlterCtxR
	fragments []rpcResponseFrag
}

type protocol struct {
	host           string
	conn           net.Conn
	mu             sync.Mutex
	dcom           *dcomState
	currentIPID    string
	remUnknownIPID string
	authnHint      uint16
	authType       byte
	authLevel      byte
	contextID      uint32
	flags          uint32
	clientSeal     *ntlmSeal
	serverSeal     *ntlmSeal
	clientSign     *ntlmSeal
	krbSessionKey  []byte
	krbEType       int
	krbWrap        func(seqNum uint32, data []byte) ([]byte, []byte, error)
	krbUnwrap      func(cipherText, authData []byte) ([]byte, error)
}

func dialProtocol(ctx context.Context, host string, port int) (*protocol, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}
	return &protocol{host: host, conn: conn, dcom: newDCOMState()}, nil
}

func (p *protocol) close() error {
	if p == nil || p.conn == nil {
		return nil
	}
	return p.conn.Close()
}

func (p *protocol) writeOnly(ctx context.Context, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if deadline, ok := ctx.Deadline(); ok {
		_ = p.conn.SetDeadline(deadline)
	} else {
		_ = p.conn.SetDeadline(time.Time{})
	}
	if common, err := parseRPCCommon(data); err == nil {
		debugf(
			"rpc write_only host=%s call_id=%d ptype=%d frag_len=%d auth_len=%d",
			p.host,
			common.callID,
			common.ptype,
			common.fragLength,
			common.authLength,
		)
	}
	_, err := p.conn.Write(data)
	return err
}

func (p *protocol) roundTrip(ctx context.Context, request []byte) (*rpcReply, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if deadline, ok := ctx.Deadline(); ok {
		_ = p.conn.SetDeadline(deadline)
	} else {
		_ = p.conn.SetDeadline(time.Time{})
	}
	if reqCommon, err := parseRPCCommon(request); err == nil {
		debugf(
			"rpc send host=%s call_id=%d ptype=%d frag_len=%d auth_len=%d",
			p.host,
			reqCommon.callID,
			reqCommon.ptype,
			reqCommon.fragLength,
			reqCommon.authLength,
		)
	}
	if _, err := p.conn.Write(request); err != nil {
		return nil, err
	}
	full, common, err := readRPCFragment(p.conn)
	if err != nil {
		return nil, err
	}
	debugf(
		"rpc recv host=%s call_id=%d ptype=%d frag_len=%d auth_len=%d flags=0x%02x",
		p.host,
		common.callID,
		common.ptype,
		common.fragLength,
		common.authLength,
		common.pfcFlags,
	)
	switch common.ptype {
	case msrpcBindAck:
		ack, err := parseRPCBindAck(p.dcom, common, full)
		if err != nil {
			return nil, err
		}
		return &rpcReply{ptype: common.ptype, bindAck: ack}, nil
	case msrpcBindNak:
		return nil, parseRPCBindNak(full)
	case msrpcAlterCtxR:
		resp, err := parseRPCAlterCtxR(p.dcom, common, full)
		if err != nil {
			return nil, err
		}
		return &rpcReply{ptype: common.ptype, alterCtxR: resp}, nil
	case msrpcFault:
		status := uint32(rpcSecPkgError)
		body := full[16:]
		switch {
		case len(body) >= 12:
			status = binary.LittleEndian.Uint32(body[8:12])
		case len(body) >= 4:
			status = binary.LittleEndian.Uint32(body[:4])
		}
		debugf(
			"rpc fault host=%s call_id=%d status=0x%08x body_prefix=%s",
			p.host,
			common.callID,
			status,
			previewHex(body, 16),
		)
		return nil, rpcError(status)
	case msrpcResponse:
		var frags []rpcResponseFrag
		body := append([]byte(nil), full[24:]...)
		frags = append(frags, rpcResponseFrag{common: common, body: body})
		for common.pfcFlags&pfcLastFrag == 0 {
			full, common, err = readRPCFragment(p.conn)
			if err != nil {
				return nil, err
			}
			if common.ptype != msrpcResponse {
				return nil, fmt.Errorf("unexpected RPC fragment type %d", common.ptype)
			}
			frags = append(frags, rpcResponseFrag{common: common, body: append([]byte(nil), full[24:]...)})
		}
		return &rpcReply{ptype: msrpcResponse, fragments: frags}, nil
	default:
		return nil, fmt.Errorf("unsupported RPC ptype %d", common.ptype)
	}
}

func readRPCFragment(r io.Reader) ([]byte, *rpcCommon, error) {
	header := make([]byte, 16)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, nil, err
	}
	common, err := parseRPCCommon(header)
	if err != nil {
		return nil, nil, err
	}
	frag := make([]byte, int(common.fragLength))
	copy(frag, header)
	if _, err := io.ReadFull(r, frag[16:]); err != nil {
		return nil, nil, err
	}
	return frag, common, nil
}

func (p *protocol) responseMessage(frags []rpcResponseFrag) ([]byte, error) {
	var out []byte
	for _, frag := range frags {
		body := frag.body
		if frag.common.authLength > 0 {
			offset := len(body) - int(frag.common.authLength) - 8
			if offset < 0 {
				return nil, errors.New("invalid RPC auth trailer")
			}
			auth, err := parseRPCAuthVerifier(body, frag.common.authLength, offset)
			if err != nil {
				debugf(
					"rpc response auth parse failed call_id=%d auth_len=%d body_len=%d offset=%d err=%v",
					frag.common.callID,
					frag.common.authLength,
					len(body),
					offset,
					err,
				)
				return nil, err
			}
			debugf(
				"rpc response auth call_id=%d auth_type=%d auth_level=%d auth_pad=%d auth_ctx=%d cipher_len=%d",
				frag.common.callID,
				auth.authType,
				auth.authLevel,
				auth.authPadLength,
				auth.authContextID,
				offset,
			)
			cipherText := body[:offset]
			switch {
			case auth.authLevel == rpcCAuthNLevelPktPrivacy && auth.authType == rpcCAuthNWinNT:
				msg, _ := p.serverSeal.seal(p.flags, p.dcom.seqNum, cipherText, cipherText)
				body = msg
			case auth.authLevel == rpcCAuthNLevelPktPrivacy && auth.authType == rpcCAuthNGSSNegotiate:
				if p.krbUnwrap == nil {
					return nil, errors.New("kerberos unwrap function is not configured")
				}
				msg, err := p.krbUnwrap(cipherText, auth.authValue)
				if err != nil {
					return nil, err
				}
				body = msg
			default:
				body = cipherText
			}
			if auth.authPadLength > 0 && int(auth.authPadLength) <= len(body) {
				body = body[:len(body)-int(auth.authPadLength)]
			}
		}
		out = append(out, body...)
	}
	if len(out) < 4 {
		return nil, errors.New("short RPC response body")
	}
	code := binary.LittleEndian.Uint32(out[len(out)-4:])
	if code != 0 {
		return nil, wbemError(code)
	}
	return out, nil
}
