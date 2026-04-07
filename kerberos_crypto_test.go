package wmi

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNFold(t *testing.T) {
	cases := []struct {
		in   string
		out  string
		size int
	}{
		{"012345", "be072631276b1955", 8},
		{"kerberos", "6b65726265726f737b9b5b2b93132b93", 16},
	}
	for _, tc := range cases {
		got := nFold([]byte(tc.in), tc.size)
		require.Equal(t, tc.out, hex.EncodeToString(got), "nFold(%q,%d)", tc.in, tc.size)
	}
}

func TestAESCTS(t *testing.T) {
	key := mustHex("636869636b656e207465726979616b69")
	cases := []struct {
		plain  string
		cipher string
	}{
		{
			"4920776f756c64206c696b652074686520",
			"c6353568f2bf8cb4d8a580362da7ff7f97",
		},
		{
			"4920776f756c64206c696b65207468652047656e6572616c20476175277320",
			"fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5",
		},
		{
			"4920776f756c64206c696b65207468652047656e6572616c2047617527732043",
			"39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584",
		},
	}
	for _, tc := range cases {
		plain := mustHex(tc.plain)
		want := mustHex(tc.cipher)
		got, err := aesCTSEncrypt(key, plain)
		require.NoError(t, err)
		require.True(t, bytes.Equal(got, want), "aesCTSEncrypt(%x) = %x, want %x", plain, got, want)
		back, err := aesCTSDecrypt(key, got)
		require.NoError(t, err)
		require.True(t, bytes.Equal(back, plain), "aesCTSDecrypt roundtrip mismatch: got %x want %x", back, plain)
	}
}

func TestAESStringToKey(t *testing.T) {
	cases := []struct {
		password string
		salt     string
		keyLen   int
		iter     int
		want     string
	}{
		{"password", "ATHENA.MIT.EDUraeburn", 16, 1200, "4c01cd46d632d01e6dbe230a01ed642a"},
		{
			"password",
			"ATHENA.MIT.EDUraeburn",
			32,
			1200,
			"55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a",
		},
		{
			"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			"pass phrase equals block size",
			16,
			1200,
			"59d1bb789a828b1aa54ef9c2883f69ed",
		},
	}
	for _, tc := range cases {
		got := aesStringToKeyIter(tc.password, tc.salt, tc.keyLen, tc.iter)
		require.Equal(
			t,
			tc.want,
			hex.EncodeToString(got),
			"aesStringToKeyIter(%q,%q,%d,%d)",
			tc.password,
			tc.salt,
			tc.keyLen,
			tc.iter,
		)
	}
}

func TestKerberosEncryptRoundTrip(t *testing.T) {
	key := mustHex("55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a")
	plain := []byte("kerberos-test-payload")
	ct, err := encryptKerberosAESCTS(key, 11, plain, bytes.Repeat([]byte{0xaa}, 16))
	require.NoError(t, err)
	pt, err := decryptKerberosAESCTS(key, 11, ct)
	require.NoError(t, err)
	require.True(t, bytes.Equal(pt[16:], plain), "unexpected AES roundtrip payload: %x", pt)

	rc4Key := mustHex("ac8e657f83df82beea5d43bdaf7800cc")
	rc4ct, err := encryptKerberosRC4(rc4Key, 11, plain)
	require.NoError(t, err)
	rc4pt, err := decryptKerberosRC4(rc4Key, 11, rc4ct)
	require.NoError(t, err)
	require.True(t, bytes.Equal(rc4pt, plain), "unexpected RC4 roundtrip payload: %x", rc4pt)
}

func TestReadSessionKey(t *testing.T) {
	keyBytes := mustHex("00112233445566778899aabbccddeeff")
	payload := append(bytes.Repeat([]byte{0}, 16), asn1App(25, asn1Seq(
		append(asn1Tag(0, asn1Seq(
			append(asn1Tag(0, asn1Int(18)), asn1Tag(1, asn1OctetString(keyBytes))...),
		)), asn1Tag(1, asn1GeneralizedTime([]byte("20260101000000Z")))...),
	))...)
	got, err := readSessionKey(payload)
	require.NoError(t, err)
	require.True(t, bytes.Equal(got, keyBytes), "unexpected session key: %x", got)
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
