package wmi

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// connection holds the parameters and state for a WMI connection to a remote host.
type connection struct {
	host      string
	port      int
	username  string
	password  string
	domain    string
	namespace string
	kdcHost   string
	kdcPort   int

	base          *protocol
	kerberosCache *KerberosCache
}

// service represents an authenticated WMI service binding.
type service struct {
	proto *protocol
}

// newConnection creates a new connection with sensible defaults.
func newConnection(host, username, password string) *connection {
	return &connection{
		host:          host,
		port:          135,
		username:      username,
		password:      password,
		namespace:     defaultNamespace,
		kdcHost:       host,
		kdcPort:       88,
		kerberosCache: NewKerberosCache(""),
	}
}

func (c *connection) isConnected() bool {
	return c != nil && c.base != nil
}

func (c *connection) hasValidKeys(offset ...time.Duration) bool {
	if c == nil || c.kerberosCache == nil {
		return false
	}
	return c.kerberosCache.HasValidKeys(offset...)
}

func (c *connection) setKerberosCache(cache *KerberosCache) {
	if cache == nil {
		cache = NewKerberosCache("")
	}
	c.kerberosCache = cache
}

func (c *connection) setKerberosCacheFile(filePath string) {
	c.setKerberosCache(NewKerberosCache(filePath))
}

func (c *connection) dial(ctx context.Context) error {
	if c.base != nil {
		return nil
	}
	debugf("connect start host=%s port=%d", c.host, c.port)
	p, err := dialProtocol(ctx, c.host, c.port)
	if err != nil {
		debugf("connect failed host=%s port=%d err=%v", c.host, c.port, err)
		return err
	}
	c.base = p
	debugf("connect ok host=%s port=%d", c.host, c.port)
	return nil
}

func (c *connection) close() error {
	if c.base == nil {
		return nil
	}
	err := c.base.close()
	c.base = nil
	return err
}

func (s *service) close() error {
	if s == nil || s.proto == nil {
		return nil
	}
	return s.proto.close()
}

func (c *connection) negotiateKerberos(ctx context.Context) (*service, error) {
	if c.domain == "" {
		return nil, errors.New("domain is required for Kerberos authentication")
	}
	if err := c.dial(ctx); err != nil {
		return nil, err
	}
	p := c.base
	p.authLevel = rpcCAuthNLevelPktPrivacy
	p.contextID = 79231
	debugf(
		"kerberos negotiate start host=%s context_id=%d auth_level=%d cache_valid=%v",
		c.host,
		p.contextID,
		p.authLevel,
		c.kerberosCache.hasValidKeys(90*time.Second),
	)

	if !c.kerberosCache.hasValidKeys(90 * time.Second) {
		asRepBytes, baseKey, err := getTGT(ctx, c.username, c.password, c.domain, c.kdcHost, c.kdcPort)
		if err != nil {
			return nil, err
		}
		ticket, serviceKey, etype, expiresAt, err := getTGS(
			ctx,
			c.username,
			c.domain,
			c.host,
			asRepBytes,
			baseKey,
			c.kdcHost,
			c.kdcPort,
		)
		if err != nil {
			return nil, err
		}
		c.kerberosCache.setTGT(asRepBytes, baseKey)
		c.kerberosCache.setTGS(ticket, serviceKey, etype, expiresAt)
		_ = c.kerberosCache.Save()
	}

	if err := c.bindKerberos(ctx, p, iidIRemoteSCMActivator); err != nil {
		debugf("kerberos bind scm failed err=%v", err)
		return nil, err
	}
	svcProto, err := c.ifBinding(ctx, p, rpcCAuthNLevelPktPrivacy, c.bindKerberos)
	if err != nil {
		debugf("kerberos interface binding failed err=%v", err)
		return nil, err
	}
	if err := c.loginNTLM(ctx, &service{proto: svcProto}, "root/cimv2"); err != nil {
		debugf("kerberos post-bind login failed err=%v", err)
		_ = svcProto.close()
		return nil, err
	}
	debugf("kerberos negotiate ok service_context_id=%d current_ipid=%s", svcProto.contextID, svcProto.currentIPID)
	return &service{proto: svcProto}, nil
}

func (c *connection) negotiateNTLM(ctx context.Context) (*service, error) {
	svc, err := c.negotiateNTLMAuth(ctx, rpcCAuthNLevelPktPrivacy)
	if err == nil || !shouldRetryNTLMActivation(err) {
		return svc, err
	}
	debugf("ntlm pkt privacy activation failed err=%v; retrying with auth_level=%d", err, rpcCAuthNLevelPktIntegrity)
	c.resetBase()
	return c.negotiateNTLMAuth(ctx, rpcCAuthNLevelPktIntegrity)
}

func (c *connection) negotiateNTLMAuth(ctx context.Context, authLevel byte) (*service, error) {
	if err := c.dial(ctx); err != nil {
		return nil, err
	}
	p := c.base
	p.authLevel = authLevel
	p.contextID = 4242
	debugf("ntlm negotiate start host=%s context_id=%d auth_level=%d", c.host, p.contextID, p.authLevel)
	if err := c.bindNTLM(ctx, p, iidIRemoteSCMActivator); err != nil {
		debugf("ntlm bind scm failed err=%v", err)
		return nil, err
	}
	svcProto, err := c.ifBinding(ctx, p, rpcCAuthNLevelPktIntegrity, c.bindNTLM)
	if err != nil {
		debugf("ntlm interface binding failed err=%v", err)
		return nil, err
	}
	if err := c.loginNTLM(ctx, &service{proto: svcProto}, "root/cimv2"); err != nil {
		debugf("ntlm post-bind login failed err=%v", err)
		_ = svcProto.close()
		return nil, err
	}
	debugf("ntlm negotiate ok service_context_id=%d current_ipid=%s", svcProto.contextID, svcProto.currentIPID)
	return &service{proto: svcProto}, nil
}

func (c *connection) bindNTLM(ctx context.Context, p *protocol, iid []byte) error {
	negotiate, flags := buildNTLMNegotiate()
	debugf(
		"ntlm bind send context_id=%d auth_level=%d iid=%s negotiate_len=%d flags=0x%08x",
		p.contextID,
		p.authLevel,
		previewHex(iid, 8),
		len(negotiate),
		flags,
	)
	req := newRPCBind()
	req.addContElem(rpcContElem{
		abstractSyntax:   iid,
		transferSyntaxes: [][]byte{ndrTransferSyntaxIdentifier},
	})
	authPad := mustByte(pad4(req.freeze()))
	auth, authLen := makeRPCAuthVerifier(rpcCAuthNWinNT, p.authLevel, authPad, p.contextID, negotiate)
	req.callID = p.dcom.nextCallID()
	req.setAuthVerifier(auth, authLen)

	reply, err := p.roundTrip(ctx, req.bytes())
	if err != nil {
		debugf("ntlm bind roundtrip failed err=%v", err)
		return err
	}
	challenge, err := parseNTLMChallenge(reply.bindAck.auth.authValue)
	if err != nil {
		debugf("ntlm challenge parse failed err=%v", err)
		return err
	}
	p.authType = reply.bindAck.auth.authType
	p.authLevel = reply.bindAck.auth.authLevel
	p.flags = flags
	debugf(
		"ntlm bind ack auth_type=%d auth_level=%d challenge_flags=0x%08x target_info_len=%d",
		p.authType,
		p.authLevel,
		challenge.negotiateFlags,
		len(challenge.targetInfo),
	)

	authMsg, flags, exportedSessionKey := buildNTLMAuthenticate(
		c.username,
		c.password,
		c.domain,
		c.host,
		flags,
		challenge,
	)
	if p.authLevel >= rpcCAuthNLevelConnect && p.authType == rpcCAuthNWinNT &&
		flags&ntlmSSPNegotiateExtendedSessionSecurity != 0 {
		clientSigningKey := signKey(flags, exportedSessionKey, true)
		serverSigningKey := signKey(flags, exportedSessionKey, false)
		clientSealingKey := sealKey(flags, exportedSessionKey, true)
		serverSealingKey := sealKey(flags, exportedSessionKey, false)
		clientHandle := newRC4Func(clientSealingKey)
		p.clientSeal = &ntlmSeal{signingKey: clientSigningKey, handle: clientHandle}
		p.serverSeal = &ntlmSeal{signingKey: serverSigningKey, handle: newRC4Func(serverSealingKey)}
		// NTLM integrity and privacy packets advance the same client RC4 state.
		p.clientSign = &ntlmSeal{signingKey: clientSigningKey, handle: clientHandle}
	}

	auth3 := newRPCCommon(msrpcAuth3)
	auth, authLen = makeRPCAuthVerifier(rpcCAuthNWinNT, p.authLevel, 0, p.contextID, authMsg)
	auth3.setPDUData([]byte("    "))
	auth3.callID = p.dcom.nextCallID()
	auth3.setAuthVerifier(auth, authLen)
	debugf("ntlm auth3 send call_id=%d auth_len=%d", auth3.callID, authLen)
	return p.writeOnly(ctx, auth3.bytes())
}

func (c *connection) bindKerberos(ctx context.Context, p *protocol, iid []byte) error {
	if c.kerberosCache == nil || len(c.kerberosCache.ticket) == 0 || len(c.kerberosCache.serviceKey) == 0 {
		return errors.New("kerberos cache is empty")
	}
	debugf(
		"kerberos bind send context_id=%d auth_level=%d iid=%s etype=%d ticket_len=%d",
		p.contextID,
		p.authLevel,
		previewHex(iid, 8),
		c.kerberosCache.etype,
		len(c.kerberosCache.ticket),
	)

	apReq, err := buildAPReq(
		c.username,
		c.domain,
		c.kerberosCache.ticket,
		c.kerberosCache.serviceKey,
		c.kerberosCache.etype,
	)
	if err != nil {
		return err
	}
	req := newRPCBind()
	req.addContElem(rpcContElem{
		abstractSyntax:   iid,
		transferSyntaxes: [][]byte{ndrTransferSyntaxIdentifier},
	})
	authPad := mustByte(pad4(req.freeze()))
	auth, authLen := makeRPCAuthVerifier(
		rpcCAuthNGSSNegotiate,
		p.authLevel,
		authPad,
		p.contextID,
		wrapGSSKerberos(apReq),
	)
	req.callID = p.dcom.nextCallID()
	req.setAuthVerifier(auth, authLen)

	reply, err := p.roundTrip(ctx, req.bytes())
	if err != nil {
		debugf("kerberos bind roundtrip failed err=%v", err)
		return err
	}
	p.authType = reply.bindAck.auth.authType
	p.authLevel = reply.bindAck.auth.authLevel
	debugf(
		"kerberos bind ack auth_type=%d auth_level=%d auth_len=%d",
		p.authType,
		p.authLevel,
		len(reply.bindAck.auth.authValue),
	)

	activeKey, seqNum, err := getActiveKey(
		reply.bindAck.auth.authValue,
		c.kerberosCache.serviceKey,
		c.kerberosCache.etype,
	)
	if err != nil {
		return err
	}
	if len(activeKey) == 0 {
		activeKey = append([]byte(nil), c.kerberosCache.serviceKey...)
	}
	if seqNum == 0 {
		seqNum = p.dcom.seqNum
	}
	debugf("kerberos active key len=%d seq_num=%d", len(activeKey), seqNum)
	negToken, err := getNegToken(c.kerberosCache.serviceKey, seqNum, c.kerberosCache.etype)
	if err != nil {
		return err
	}
	alter := newRPCAlterContext(iid, p.dcom.nextCallID(), rpcCAuthNGSSNegotiate, p.authLevel, p.contextID, negToken)
	if _, err := p.roundTrip(ctx, alter); err != nil {
		debugf("kerberos alter context failed err=%v", err)
		return err
	}

	p.krbSessionKey = append([]byte(nil), activeKey...)
	p.krbEType = c.kerberosCache.etype
	p.krbWrap = func(seqNum uint32, data []byte) ([]byte, []byte, error) {
		switch p.krbEType {
		case krbETypeAES128, krbETypeAES256:
			return gssWrapAES(p.krbSessionKey, data, seqNum)
		case krbETypeRC4:
			return gssWrapRC4(p.krbSessionKey, data, seqNum)
		default:
			return nil, nil, fmt.Errorf("unsupported kerberos etype %d", p.krbEType)
		}
	}
	p.krbUnwrap = func(cipherText, authData []byte) ([]byte, error) {
		switch p.krbEType {
		case krbETypeAES128, krbETypeAES256:
			return gssUnwrapAES(p.krbSessionKey, cipherText, authData)
		case krbETypeRC4:
			return gssUnwrapRC4(p.krbSessionKey, cipherText, authData)
		default:
			return nil, fmt.Errorf("unsupported kerberos etype %d", p.krbEType)
		}
	}
	return nil
}

func (c *connection) ifBinding(
	ctx context.Context,
	base *protocol,
	minAuthLevel byte,
	binder func(context.Context, *protocol, []byte) error,
) (*protocol, error) {
	debugf("if_binding start base_context_id=%d min_auth_level=%d", base.contextID, minAuthLevel)
	blob := newActivationBlob()
	blob.addInfoData(newInstantiationInfoData(clsidIWbemLevel1Login, iidIWbemLevel1Login))
	blob.addInfoData(locationInfoData())
	blob.addInfoData(activationContextInfoData())
	blob.addInfoData(scmRequestInfoData())

	obj := newObjRefCustom()
	obj.setObject(blob.bytes())
	objBytes := obj.bytes()

	pdu := bytes.NewBuffer(nil)
	pdu.Write(orpcthis(1))
	_ = binary.Write(pdu, binary.LittleEndian, uint32(0))
	_ = binary.Write(pdu, binary.LittleEndian, genReferentID())
	_ = binary.Write(pdu, binary.LittleEndian, mustUint32(len(objBytes)))
	_ = binary.Write(pdu, binary.LittleEndian, mustUint32(len(objBytes)))
	pdu.Write(objBytes)

	req := newRPCRequest(4, "")
	req.setAppData(pdu.Bytes())
	wire, err := signOrSealRequest(req, base, 0)
	if err != nil {
		return nil, err
	}
	reply, err := base.roundTrip(ctx, wire)
	if err != nil {
		debugf("if_binding remote create instance failed err=%v", err)
		return nil, err
	}
	msg, err := base.responseMessage(reply.fragments)
	if err != nil {
		return nil, err
	}
	activate, err := parseRemoteCreateInstanceResponse(c.host, msg)
	if err != nil {
		return nil, err
	}

	host, port, err := activate.binding()
	if err != nil {
		return nil, err
	}
	debugf(
		"if_binding selected binding host=%s port=%d authn_hint=%d ipid=%s",
		host,
		port,
		activate.authnHint,
		activate.ipid,
	)

	p, err := dialProtocol(ctx, c.host, port)
	if err != nil {
		p, err = dialProtocol(ctx, host, port)
		if err != nil {
			return nil, err
		}
	}
	p.authLevel = mustByteFromUint16(maxUint16(uint16(minAuthLevel), activate.authnHint))
	p.contextID = base.contextID + 1
	debugf(
		"if_binding new protocol host=%s port=%d context_id=%d auth_level=%d",
		p.host,
		port,
		p.contextID,
		p.authLevel,
	)
	if err := binder(ctx, p, iidIWbemLevel1Login); err != nil {
		_ = p.close()
		return nil, err
	}
	p.currentIPID = activate.ipid
	p.remUnknownIPID = activate.remUnknownIPID
	p.authnHint = activate.authnHint
	return p, nil
}

func (c *connection) loginNTLM(ctx context.Context, svc *service, namespace string) error {
	if svc == nil || svc.proto == nil {
		return errors.New("service is nil")
	}
	namespace = normalizeNamespace(namespace)
	var preferred *string
	pdu := bytes.NewBuffer(nil)
	pdu.Write(orpcthis(0))
	pdu.Write(lpwStr(&namespace))
	pdu.Write(lpwStr(preferred))
	_ = binary.Write(pdu, binary.LittleEndian, int32(0))
	pdu.Write(getNull())

	req := newRPCRequest(6, svc.proto.currentIPID)
	req.setAppData(pdu.Bytes())
	debugf(
		"login start namespace=%s ipid=%s app_len=%d auth_type=%d auth_level=%d",
		namespace,
		svc.proto.currentIPID,
		len(pdu.Bytes()),
		svc.proto.authType,
		svc.proto.authLevel,
	)
	wire, err := req.signData(svc.proto)
	if err != nil {
		return err
	}
	reply, err := svc.proto.roundTrip(ctx, wire)
	if err != nil {
		return err
	}
	msg, err := svc.proto.responseMessage(reply.fragments)
	if err != nil {
		return err
	}
	resp, err := parseSimpleInterfaceResponse(msg)
	if err != nil {
		return err
	}
	svc.proto.currentIPID = resp.ipid
	c.namespace = namespace
	debugf("login ok namespace=%s new_ipid=%s", namespace, resp.ipid)
	return nil
}

func (p *protocol) remRelease(ctx context.Context, ipid string) error {
	if p.remUnknownIPID == "" {
		return nil
	}
	ipidBin, err := uuidToBin(ipid)
	if err != nil {
		return err
	}
	pdu := bytes.NewBuffer(nil)
	pdu.Write(orpcthis(0))
	pdu.Write([]byte{0x01, 0x00, 0xce, 0xce, 0x01, 0x00, 0x00, 0x00})
	pdu.Write(ipidBin)
	_ = binary.Write(pdu, binary.LittleEndian, uint32(1))
	_ = binary.Write(pdu, binary.LittleEndian, uint32(0))

	req := newRPCRequest(5, p.remUnknownIPID)
	req.setAppData(pdu.Bytes())
	wire, err := req.signData(p)
	if err != nil {
		return err
	}
	reply, err := p.roundTrip(ctx, wire)
	if err != nil {
		return err
	}
	_, err = p.responseMessage(reply.fragments)
	return err
}

func maxUint16(a, b uint16) uint16 {
	if a > b {
		return a
	}
	return b
}

func (c *connection) resetBase() {
	if c.base == nil {
		return
	}
	_ = c.base.close()
	c.base = nil
}

func shouldRetryNTLMActivation(err error) bool {
	return errors.Is(err, &Error{Code: rpcSecPkgError})
}

func signOrSealRequest(req *rpcRequest, proto *protocol, ctxID uint16) ([]byte, error) {
	switch proto.authLevel {
	case rpcCAuthNLevelPktPrivacy:
		return req.sealData(proto, ctxID)
	case rpcCAuthNLevelPktIntegrity:
		return req.signData(proto)
	default:
		return nil, fmt.Errorf("unsupported request auth_level=%d", proto.authLevel)
	}
}
