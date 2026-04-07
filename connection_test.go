package wmi

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShouldRetryNTLMActivation(t *testing.T) {
	require.True(
		t,
		shouldRetryNTLMActivation(rpcError(rpcSecPkgError)),
		"expected rpc sec pkg error to trigger NTLM activation retry",
	)
	require.False(
		t,
		shouldRetryNTLMActivation(rpcError(rpcAccessDenied)),
		"did not expect access denied to trigger NTLM activation retry",
	)
	require.False(t, shouldRetryNTLMActivation(nil), "did not expect nil error to trigger NTLM activation retry")
}

func TestSignOrSealRequestUsesIntegrityForSignedActivation(t *testing.T) {
	req := newRPCRequest(4, "")
	req.setAppData([]byte{1, 2, 3, 4})

	proto := &protocol{
		authType:  rpcCAuthNWinNT,
		authLevel: rpcCAuthNLevelPktIntegrity,
		contextID: 4242,
		flags:     ntlmSSPNegotiateExtendedSessionSecurity,
		dcom:      newDCOMState(),
		clientSign: &ntlmSeal{
			signingKey: make([]byte, 16),
			handle:     newRC4Func(make([]byte, 16)),
		},
	}

	wire, err := signOrSealRequest(req, proto, 0)
	require.NoError(t, err)
	common, err := parseRPCCommon(wire)
	require.NoError(t, err)
	require.EqualValues(t, 16, common.authLength)
	body := wire[16:]
	auth, err := parseRPCAuthVerifier(body, common.authLength, len(body)-int(common.authLength)-8)
	require.NoError(t, err)
	require.EqualValues(t, rpcCAuthNLevelPktIntegrity, auth.authLevel)
}
