package wmi

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestASN1Encoding(t *testing.T) {
	body := append(asn1Tag(0, asn1Int(5)), asn1Tag(1, asn1GeneralString([]byte("EXAMPLE.COM")))...)
	got := asn1Seq(body)
	want := mustHex("3014a003020105a10d1b0b4558414d504c452e434f4d")
	require.True(t, bytes.Equal(got, want), "unexpected DER:\n got %x\nwant %x", got, want)

	long := asn1OctetString(bytes.Repeat([]byte{0xaa}, 128))
	require.Equal(t, []byte{0x04, 0x81, 0x80}, long[:3], "unexpected long-form DER prefix")

	l, n, err := getASN1Len(long, 1)
	require.NoError(t, err)
	require.Equal(t, 128, l)
	require.Equal(t, 2, n)
}
