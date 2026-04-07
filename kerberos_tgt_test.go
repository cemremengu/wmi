package wmi

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildASReq(t *testing.T) {
	packet := buildASReq("alice", "example.com")
	root, err := parseASN1(packet, 0)
	require.NoError(t, err)
	require.Equal(t, byte(0x6a), root.tag, "unexpected AS-REQ tag")
	seq, err := parseASN1(root.content, 0)
	require.NoError(t, err)
	for _, tag := range []byte{0xa1, 0xa2, 0xa3, 0xa4} {
		_, ok, err := findASN1Child(seq.content, tag)
		require.NoError(t, err)
		require.True(t, ok, "missing AS-REQ field tag %#x", tag)
	}
}

func TestBuildFullASReqAndWrapGSS(t *testing.T) {
	baseKey := mustHex("55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a")
	packet, err := buildFullASReq("alice", "example.com", baseKey, krbETypeAES256)
	require.NoError(t, err)
	require.True(t, bytes.Contains(packet, []byte{0x02, 0x01, 0x02}), "PA-ENC-TIMESTAMP marker missing: %x", packet)
	require.True(t,
		bytes.Contains(packet, []byte{0x02, 0x02, 0x00, 0x80}) || bytes.Contains(packet, []byte{0x02, 0x01, 0x80}),
		"PA-PAC-REQUEST marker missing: %x", packet,
	)

	gss := wrapGSSKerberos([]byte{0x6e, 0x00})
	require.True(t, len(gss) > 0 && gss[0] == 0x60, "unexpected GSS wrapper: %x", gss)
	require.True(t, bytes.Contains(gss, oidSPNEGO), "SPNEGO OID missing from GSS wrapper: %x", gss)
}
