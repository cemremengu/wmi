package wmi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type infoData interface {
	CLSID() []byte
	bytes() []byte
}

type rawInfoData struct {
	clsid []byte
	data  []byte
}

func (r rawInfoData) CLSID() []byte { return r.clsid }
func (r rawInfoData) bytes() []byte { return r.data }

type activationBlob struct {
	destCtx    uint32
	pclsid     [][]byte
	psizes     []uint32
	properties [][]byte
}

func newActivationBlob() *activationBlob { return &activationBlob{destCtx: 2} }

func (a *activationBlob) addInfoData(info infoData) {
	data := info.bytes()
	a.pclsid = append(a.pclsid, append([]byte(nil), info.CLSID()...))
	a.psizes = append(a.psizes, mustUint32(len(data)))
	a.properties = append(a.properties, data)
}

func (a *activationBlob) bytes() []byte {
	clsids := bytes.Join(a.pclsid, nil)
	props := bytes.Join(a.properties, nil)
	psizes := bytes.NewBuffer(nil)
	_ = binary.Write(psizes, binary.LittleEndian, mustUint32(len(a.psizes)))
	for _, size := range a.psizes {
		_ = binary.Write(psizes, binary.LittleEndian, size)
	}

	headerSize := 8 + 8 + 20 + 16 + 16 + len(clsids) + psizes.Len()
	totalSize := headerSize + len(props)

	buf := bytes.NewBuffer(nil)
	_ = binary.Write(buf, binary.LittleEndian, mustUint32(totalSize))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	buf.Write(ndrCommonHeader())
	buf.Write(ndrPrivateHeader(headerSize - 16))
	_ = binary.Write(buf, binary.LittleEndian, mustUint32(totalSize))
	_ = binary.Write(buf, binary.LittleEndian, mustUint32(headerSize))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(buf, binary.LittleEndian, a.destCtx)
	_ = binary.Write(buf, binary.LittleEndian, mustUint32(len(a.pclsid)))
	buf.Write(make([]byte, 16))
	_ = binary.Write(buf, binary.LittleEndian, genReferentID())
	_ = binary.Write(buf, binary.LittleEndian, genReferentID())
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(buf, binary.LittleEndian, mustUint32(len(a.pclsid)))
	buf.Write(clsids)
	buf.Write(psizes.Bytes())
	buf.Write(bytes.Repeat([]byte{0xfa}, pad8(headerSize-16)))
	buf.Write(props)
	return buf.Bytes()
}

func parseActivationBlob(data []byte) (*activationBlob, error) {
	if len(data) < 52 {
		return nil, errors.New("short activation blob")
	}
	offset := 0
	offset += 8
	offset += 8
	offset += 8
	offset += 20
	offset += 16
	cClsids := int(binary.LittleEndian.Uint32(data[offset+12:]))
	offset += 16
	blob := &activationBlob{}
	for range cClsids {
		blob.pclsid = append(blob.pclsid, append([]byte(nil), data[offset:offset+16]...))
		offset += 16
	}
	nPSizes := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	for range nPSizes {
		size := binary.LittleEndian.Uint32(data[offset:])
		offset += 4
		blob.psizes = append(blob.psizes, size)
	}
	for _, size := range blob.psizes {
		if offset+int(size) > len(data) {
			return nil, errors.New("short activation property")
		}
		blob.properties = append(blob.properties, append([]byte(nil), data[offset:offset+int(size)]...))
		offset += int(size)
	}
	return blob, nil
}

func ndrCommonHeader() []byte {
	buf := make([]byte, 8)
	buf[0] = 1
	buf[1] = 0x10
	binary.LittleEndian.PutUint16(buf[2:4], 8)
	binary.LittleEndian.PutUint32(buf[4:8], 0xcccccccc)
	return buf
}

func ndrPrivateHeader(size int) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint32(buf[0:4], mustUint32(size))
	binary.LittleEndian.PutUint32(buf[4:8], 0xcccccccc)
	return buf
}

func newInstantiationInfoData(classID, iid []byte) infoData {
	referentID := genReferentID()
	thisSize := 8 + 8 + 16 + 32 + len(iid)
	thisSize += pad8(thisSize)
	bodySize := 16 + 36 + len(iid)
	buf := bytes.NewBuffer(nil)
	buf.Write(ndrCommonHeader())
	buf.Write(ndrPrivateHeader(bodySize))
	buf.Write(classID)
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(buf, binary.LittleEndian, int32(0))
	_ = binary.Write(buf, binary.LittleEndian, uint32(1))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(buf, binary.LittleEndian, referentID)
	_ = binary.Write(buf, binary.LittleEndian, mustUint32(thisSize))
	_ = binary.Write(buf, binary.LittleEndian, uint16(comVersionMajor))
	_ = binary.Write(buf, binary.LittleEndian, uint16(comVersionMinor))
	_ = binary.Write(buf, binary.LittleEndian, uint32(1))
	buf.Write(iid)
	buf.Write(bytes.Repeat([]byte{0xfa}, pad8(bodySize)))
	return rawInfoData{clsid: clsidInstantiationInfo, data: buf.Bytes()}
}

func locationInfoData() infoData {
	buf := bytes.NewBuffer(nil)
	buf.Write(ndrCommonHeader())
	buf.Write(ndrPrivateHeader(16))
	buf.Write(make([]byte, 16))
	return rawInfoData{clsid: clsidServerLocationInfo, data: buf.Bytes()}
}

func activationContextInfoData() infoData {
	buf := bytes.NewBuffer(nil)
	buf.Write(ndrCommonHeader())
	buf.Write(ndrPrivateHeader(24))
	buf.Write(make([]byte, 24))
	return rawInfoData{clsid: clsidActivationContextInfo, data: buf.Bytes()}
}

func scmRequestInfoData() infoData {
	const bodySize = 26
	buf := bytes.NewBuffer(nil)
	buf.Write(ndrCommonHeader())
	buf.Write(ndrPrivateHeader(bodySize))
	_ = binary.Write(buf, binary.LittleEndian, int32(0))
	_ = binary.Write(buf, binary.LittleEndian, genReferentID())
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(buf, binary.LittleEndian, uint16(1))
	buf.Write([]byte{0xaa, 0xaa})
	_ = binary.Write(buf, binary.LittleEndian, genReferentID())
	_ = binary.Write(buf, binary.LittleEndian, uint32(1))
	_ = binary.Write(buf, binary.LittleEndian, uint16(7))
	buf.Write(bytes.Repeat([]byte{0xfa}, pad8(bodySize)))
	return rawInfoData{clsid: clsidScmRequestInfo, data: buf.Bytes()}
}

func orpcthis(flags uint32) []byte {
	buf := bytes.NewBuffer(nil)
	_ = binary.Write(buf, binary.LittleEndian, uint16(comVersionMajor))
	_ = binary.Write(buf, binary.LittleEndian, uint16(comVersionMinor))
	_ = binary.Write(buf, binary.LittleEndian, flags)
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	buf.Write(genCID())
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	return buf.Bytes()
}

func parseORPCTHAT(data []byte) (int, error) {
	if len(data) < 8 {
		return 0, errors.New("short ORPCTHAT")
	}
	extensions := binary.LittleEndian.Uint32(data[4:])
	if extensions != 0 {
		return 8, ErrNotImplemented
	}
	return 8, nil
}

type objRefStandard struct {
	ipid      string
	saResAddr []byte
}

type objRefCustom struct {
	objectReferenceSize uint32
	objectData          []byte
}

func newObjRefCustom() *objRefCustom { return &objRefCustom{} }

func (o *objRefCustom) setObject(blob []byte) {
	o.objectData = append([]byte(nil), blob...)
	o.objectReferenceSize = mustUint32(len(blob) + 8)
}

func (o *objRefCustom) bytes() []byte {
	buf := bytes.NewBuffer(nil)
	_ = binary.Write(buf, binary.LittleEndian, uint32(0x574f454d))
	_ = binary.Write(buf, binary.LittleEndian, uint32(flagsObjrefCustom))
	buf.Write(uuidPart(iidIActivationPropertiesIn))
	buf.Write(clsidActivationPropertiesIn)
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(buf, binary.LittleEndian, o.objectReferenceSize)
	buf.Write(o.objectData)
	return buf.Bytes()
}

func parseObjRef(data []byte, offset int, size int) (*objRefStandard, *objRefCustom, error) {
	if offset+24 > len(data) {
		return nil, nil, errors.New("short OBJREF")
	}
	flags := binary.LittleEndian.Uint32(data[offset+4:])
	switch {
	case flags&flagsObjrefStandard != 0:
		return parseObjRefStandard(data, offset, size)
	case flags&flagsObjrefCustom != 0:
		return nil, parseObjRefCustom(data, offset, size), nil
	default:
		return nil, nil, fmt.Errorf("unsupported OBJREF flags 0x%x", flags)
	}
}

func parseObjRefStandard(data []byte, offset int, size int) (*objRefStandard, *objRefCustom, error) {
	end := offset + size
	if size < 40 || end > len(data) {
		return nil, nil, errors.New("short OBJREF_STANDARD")
	}
	offset += 24
	if offset+40 > len(data) {
		return nil, nil, errors.New("short OBJREF_STANDARD")
	}
	offset += 4
	cPublicRefs := binary.LittleEndian.Uint32(data[offset:])
	if cPublicRefs == 0 {
		return nil, nil, errors.New("public reference counter is zero")
	}
	offset += 4
	offset += 8
	offset += 8
	ipid := binToUUID(data, offset)
	offset += 16
	return &objRefStandard{ipid: ipid, saResAddr: append([]byte(nil), data[offset:end]...)}, nil, nil
}

func parseObjRefCustom(data []byte, offset int, size int) *objRefCustom {
	end := offset + size
	if size < 32 || end > len(data) {
		return &objRefCustom{}
	}
	offset += 24
	offset += 16
	offset += 4
	objSize := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	return &objRefCustom{objectReferenceSize: objSize, objectData: append([]byte(nil), data[offset:end]...)}
}

type simpleInterfaceResponse struct{ ipid string }

func parseSimpleInterfaceResponse(data []byte) (*simpleInterfaceResponse, error) {
	offset, err := parseORPCTHAT(data)
	if err != nil {
		return nil, err
	}
	if offset+12 > len(data) {
		return nil, errors.New("short interface response")
	}
	size := int(binary.LittleEndian.Uint32(data[offset+8:]))
	offset += 12
	std, _, err := parseObjRef(data, offset, size)
	if err != nil {
		return nil, err
	}
	offset += size + pad4(size)
	if offset+4 > len(data) {
		return nil, errors.New("short interface response code")
	}
	if code := binary.LittleEndian.Uint32(data[offset:]); code != 0 {
		return nil, wbemError(code)
	}
	return &simpleInterfaceResponse{ipid: std.ipid}, nil
}

type remoteCreateInstanceResponse struct {
	ipid           string
	remUnknownIPID string
	authnHint      uint16
	strBindings    [][2]any
	target         string
}

func parseRemoteCreateInstanceResponse(target string, data []byte) (*remoteCreateInstanceResponse, error) {
	offset, err := parseORPCTHAT(data)
	if err != nil {
		return nil, err
	}
	if offset+12 > len(data) {
		return nil, errors.New("short remote create response")
	}
	size := int(binary.LittleEndian.Uint32(data[offset+8:]))
	offset += 12
	_, custom, err := parseObjRef(data, offset, size)
	if err != nil {
		return nil, err
	}
	offset += size + pad4(size)
	if offset+4 > len(data) {
		return nil, errors.New("short remote create response code")
	}
	if code := binary.LittleEndian.Uint32(data[offset:]); code != 0 {
		return nil, wbemError(code)
	}
	blob, err := parseActivationBlob(custom.objectData)
	if err != nil {
		return nil, err
	}
	if len(blob.properties) < 2 {
		return nil, errors.New("remote activation missing properties")
	}
	ipid, err := parsePropsOutInfo(blob.properties[0])
	if err != nil {
		return nil, err
	}
	remUnknown, authnHint, bindings, err := parseScmReplyInfo(blob.properties[1])
	if err != nil {
		return nil, err
	}
	upTarget := strings.ToUpper(target)
	if isFQDN(target) {
		if i := strings.IndexByte(upTarget, '.'); i >= 0 {
			upTarget = upTarget[:i]
		}
	}
	return &remoteCreateInstanceResponse{
		ipid:           ipid,
		remUnknownIPID: remUnknown,
		authnHint:      authnHint,
		strBindings:    bindings,
		target:         upTarget,
	}, nil
}

func parsePropsOutInfo(data []byte) (string, error) {
	offset := 16
	if offset+20 > len(data) {
		return "", errors.New("short props out info")
	}
	cIfs := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 20
	offset += cIfs * 16
	if offset+24 > len(data) {
		return "", errors.New("short props out results")
	}
	dataLen := int(binary.LittleEndian.Uint32(data[offset+20:]))
	offset += 24
	std, _, err := parseObjRef(data, offset, dataLen)
	if err != nil {
		return "", err
	}
	return std.ipid, nil
}

func parseScmReplyInfo(data []byte) (string, uint16, [][2]any, error) {
	offset := 16
	if offset+32 > len(data) {
		return "", 0, nil, errors.New("short scm reply info")
	}
	offset += 4
	offset += 4
	offset += 8
	offset += 4
	remUnknown := binToUUID(data, offset)
	offset += 16
	authnHint := binary.LittleEndian.Uint16(data[offset:])
	offset += 12
	bindings, _, err := readStringBindings(data, offset)
	if err != nil {
		return "", 0, nil, err
	}
	return remUnknown, authnHint, bindings, nil
}

func (r *remoteCreateInstanceResponse) binding() (string, int, error) {
	var host string
	var port int
	for _, item := range r.strBindings {
		towerID, _ := item[0].(uint16)
		binding, _ := item[1].(string)
		if towerID != 7 {
			continue
		}
		h := binding
		p := 0
		if i := strings.IndexByte(binding, '['); i >= 0 {
			h = binding[:i]
			port, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(binding[i:], "["), "]"))
			if err != nil {
				continue
			}
			p = port
		}
		host, port = h, p
		if strings.Contains(strings.ToUpper(h), r.target) {
			break
		}
	}
	if host == "" || port == 0 {
		return "", 0, errors.New("no binding found")
	}
	return host, port, nil
}

type remQueryInterfaceResponse struct{ ipid string }

func parseRemQueryInterfaceResponse(data []byte) (*remQueryInterfaceResponse, error) {
	offset, err := parseORPCTHAT(data)
	if err != nil {
		return nil, err
	}
	if offset+16 > len(data) {
		return nil, errors.New("short rem query response")
	}
	hResult := binary.LittleEndian.Uint32(data[offset+8:])
	offset += 16
	if hResult != 0 {
		return nil, ErrServerNotOptimized
	}
	if offset+40 > len(data) {
		return nil, errors.New("short rem query objref")
	}
	if binary.LittleEndian.Uint32(data[offset+4:]) == 0 {
		return nil, errors.New("public reference counter is zero")
	}
	offset += 24
	ipid := binToUUID(data, offset)
	offset += 16
	if offset+4 > len(data) {
		return nil, errors.New("short rem query code")
	}
	if code := binary.LittleEndian.Uint32(data[offset:]); code != 0 {
		return nil, wbemError(code)
	}
	return &remQueryInterfaceResponse{ipid: ipid}, nil
}

type getSmartEnumResponse struct {
	ipid      string
	proxyGUID []byte
}

func parseGetSmartEnumResponse(data []byte) (*getSmartEnumResponse, error) {
	offset, err := parseORPCTHAT(data)
	if err != nil {
		return nil, err
	}
	if offset+12 > len(data) {
		return nil, errors.New("short smart enum response")
	}
	size := int(binary.LittleEndian.Uint32(data[offset+8:]))
	offset += 12
	std, _, err := parseObjRef(data, offset, size)
	if err != nil {
		return nil, err
	}
	offset += size + pad4(size)
	if offset+4 > len(data) {
		return nil, errors.New("short smart enum code")
	}
	if code := binary.LittleEndian.Uint32(data[offset:]); code != 0 {
		return nil, wbemError(code)
	}
	return &getSmartEnumResponse{ipid: std.ipid, proxyGUID: genCID()}, nil
}
