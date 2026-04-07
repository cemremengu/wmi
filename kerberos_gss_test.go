package wmi

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGSSWrapRoundTrips(t *testing.T) {
	data := []byte("rpc-gss-payload")

	rc4Key := mustHex("ac8e657f83df82beea5d43bdaf7800cc")
	rc4Cipher, rc4Auth, err := gssWrapRC4(rc4Key, data, 7)
	require.NoError(t, err)
	rc4Plain, err := gssUnwrapRC4(rc4Key, rc4Cipher, rc4Auth)
	require.NoError(t, err)
	require.True(t, bytes.Equal(rc4Plain, data), "unexpected RC4 roundtrip payload: %x", rc4Plain)

	aesKey := mustHex("55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a")
	aesCipher, aesAuth, err := gssWrapAES(aesKey, data, 9)
	require.NoError(t, err)
	aesPlain, err := gssUnwrapAESUsage(aesKey, aesCipher, aesAuth, 24)
	require.NoError(t, err)
	require.True(t, bytes.Equal(aesPlain, data), "unexpected AES roundtrip payload: %x", aesPlain)
}
