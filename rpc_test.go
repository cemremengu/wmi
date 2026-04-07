package wmi

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBindNakErrorFormatting(t *testing.T) {
	err := bindNakError(rpcBindNakReasonAuthTypeUnsupported, rpcSWrongAuth)
	got := err.Error()
	require.Contains(t, got, "RPC bind rejected")
	require.Contains(t, got, "AUTHENTICATION_TYPE_NOT_SUPPORTED")
	require.Contains(t, got, "RPC_S_WRONG_KIND_OF_AUTH")
}

func TestParseRPCBindNakLegacyLayout(t *testing.T) {
	packet := make([]byte, 20)
	binary.LittleEndian.PutUint16(packet[16:18], rpcBindNakReasonTemporaryCongestion)
	binary.LittleEndian.PutUint16(packet[18:20], rpcAccessDenied)
	err := parseRPCBindNak(packet)
	require.Error(t, err)
	require.Contains(t, err.Error(), "TEMPORARY_CONGESTION")
	require.Contains(t, err.Error(), "ERROR_ACCESS_DENIED")
}

func TestRPCErrorMappings(t *testing.T) {
	cases := map[uint32]string{
		rpcAccessDenied:  "ACCESS_DENIED",
		rpcSecPkgError:   "RPC_S_SEC_PKG_ERROR",
		rpcNCaServerBusy: "NCA_S_SERVER_TOO_BUSY",
	}
	for code, want := range cases {
		require.Contains(t, rpcError(code).Error(), want)
	}
}

func TestParseRPCAuthVerifierWithPadding(t *testing.T) {
	authValue := []byte("0123456789abcdef")
	wire, authLen := makeRPCAuthVerifier(
		rpcCAuthNWinNT,
		rpcCAuthNLevelPktIntegrity,
		3,
		4243,
		authValue,
	)

	got, err := parseRPCAuthVerifier(wire, authLen, 0)
	require.NoError(t, err)
	require.EqualValues(t, rpcCAuthNWinNT, got.authType)
	require.EqualValues(t, rpcCAuthNLevelPktIntegrity, got.authLevel)
	require.EqualValues(t, 3, got.authPadLength)
	require.EqualValues(t, 4243, got.authContextID)
	require.Equal(t, string(authValue), string(got.authValue))
}

func TestParseRPCAuthVerifierAtHeaderOffset(t *testing.T) {
	authValue := []byte("0123456789abcdef")
	wire, authLen := makeRPCAuthVerifier(
		rpcCAuthNWinNT,
		rpcCAuthNLevelPktPrivacy,
		2,
		4242,
		authValue,
	)

	got, err := parseRPCAuthVerifier(wire, authLen, 2)
	require.NoError(t, err)
	require.EqualValues(t, rpcCAuthNWinNT, got.authType)
	require.EqualValues(t, rpcCAuthNLevelPktPrivacy, got.authLevel)
	require.EqualValues(t, 2, got.authPadLength)
	require.EqualValues(t, 4242, got.authContextID)
	require.Equal(t, string(authValue), string(got.authValue))
}
