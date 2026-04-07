package wmi

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScmRequestInfoDataPaddingFollowsBuffer(t *testing.T) {
	data := scmRequestInfoData().bytes()
	require.Len(t, data, 48)
	for i := range 42 {
		require.NotEqual(t, byte(0xfa), data[i], "unexpected padding byte before end of buffer at offset %d", i)
	}
	for i := 42; i < 48; i++ {
		require.Equal(t, byte(0xfa), data[i], "padding byte at offset %d = 0x%02x, want 0xfa", i, data[i])
	}
}

func TestRemoteCreateInstanceLayoutReference(t *testing.T) {
	inst := newInstantiationInfoData(clsidIWbemLevel1Login, iidIWbemLevel1Login).bytes()
	loc := locationInfoData().bytes()
	actx := activationContextInfoData().bytes()
	scm := scmRequestInfoData().bytes()
	require.Len(t, inst, 88)
	require.Len(t, loc, 32)
	require.Len(t, actx, 40)
	require.Len(t, scm, 48)

	blob := newActivationBlob()
	blob.addInfoData(newInstantiationInfoData(clsidIWbemLevel1Login, iidIWbemLevel1Login))
	blob.addInfoData(locationInfoData())
	blob.addInfoData(activationContextInfoData())
	blob.addInfoData(scmRequestInfoData())
	obj := newObjRefCustom()
	obj.setObject(blob.bytes())

	pdu := bytes.NewBuffer(nil)
	pdu.Write(orpcthis(1))
	_ = binary.Write(pdu, binary.LittleEndian, uint32(0))
	_ = binary.Write(pdu, binary.LittleEndian, genReferentID())
	_ = binary.Write(pdu, binary.LittleEndian, mustUint32(len(obj.bytes())))
	_ = binary.Write(pdu, binary.LittleEndian, mustUint32(len(obj.bytes())))
	pdu.Write(obj.bytes())
	require.Len(t, blob.bytes(), 368)
	require.Len(t, obj.bytes(), 416)
	require.Len(t, pdu.Bytes(), 464)
}

func TestActivationBlobRoundTrip(t *testing.T) {
	blob := newActivationBlob()
	blob.addInfoData(newInstantiationInfoData(clsidIWbemLevel1Login, iidIWbemLevel1Login))
	blob.addInfoData(locationInfoData())
	blob.addInfoData(activationContextInfoData())
	blob.addInfoData(scmRequestInfoData())

	got, err := parseActivationBlob(blob.bytes())
	require.NoError(t, err)
	require.Len(t, got.pclsid, 4)
	require.Len(t, got.psizes, 4)
	require.Len(t, got.properties, 4)
}

func TestParsePropsOutInfoReadsObjRefAtCorrectOffset(t *testing.T) {
	ipidBin := clsidIWbemLevel1Login
	wantIPID := binToUUID(ipidBin, 0)

	objref := bytes.NewBuffer(nil)
	_ = binary.Write(objref, binary.LittleEndian, uint32(0x574f454d))
	_ = binary.Write(objref, binary.LittleEndian, uint32(flagsObjrefStandard))
	objref.Write(make([]byte, 16))
	_ = binary.Write(objref, binary.LittleEndian, uint32(0))
	_ = binary.Write(objref, binary.LittleEndian, uint32(1))
	_ = binary.Write(objref, binary.LittleEndian, uint64(0))
	_ = binary.Write(objref, binary.LittleEndian, uint64(0))
	objref.Write(ipidBin)

	p := bytes.NewBuffer(nil)
	p.Write(ndrCommonHeader())
	p.Write(ndrPrivateHeader(20 + 16 + 24 + objref.Len()))
	_ = binary.Write(p, binary.LittleEndian, uint32(1))
	_ = binary.Write(p, binary.LittleEndian, uint32(0))
	_ = binary.Write(p, binary.LittleEndian, uint32(0))
	_ = binary.Write(p, binary.LittleEndian, uint32(0))
	_ = binary.Write(p, binary.LittleEndian, uint32(1))
	p.Write(iidIWbemLevel1Login[:16])
	_ = binary.Write(p, binary.LittleEndian, uint32(1))
	_ = binary.Write(p, binary.LittleEndian, uint32(0))
	_ = binary.Write(p, binary.LittleEndian, uint32(1))
	_ = binary.Write(p, binary.LittleEndian, uint32(0))
	_ = binary.Write(p, binary.LittleEndian, uint32(objref.Len()))
	_ = binary.Write(p, binary.LittleEndian, uint32(objref.Len()))
	p.Write(objref.Bytes())

	gotIPID, err := parsePropsOutInfo(p.Bytes())
	require.NoError(t, err)
	require.Equal(t, wantIPID, gotIPID)
}

func TestParseRemQueryInterfaceResponse(t *testing.T) {
	ipidBin := clsidIWbemLevel1Login
	wantIPID := binToUUID(ipidBin, 0)

	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0})
	_ = binary.Write(buf, binary.LittleEndian, uint32(1))
	_ = binary.Write(buf, binary.LittleEndian, uint32(40))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(buf, binary.LittleEndian, uint32(1))
	_ = binary.Write(buf, binary.LittleEndian, uint64(0))
	_ = binary.Write(buf, binary.LittleEndian, uint64(0))
	buf.Write(ipidBin)
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))

	got, err := parseRemQueryInterfaceResponse(buf.Bytes())
	require.NoError(t, err)
	require.Equal(t, wantIPID, got.ipid)
}
