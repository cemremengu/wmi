package wmi

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWBEMErrorMappings(t *testing.T) {
	cases := map[uint32]string{
		wbemEInvalidObjectPath:       "WBEM_E_INVALID_OBJECT_PATH",
		wbemEOutOfDiskSpace:          "WBEM_E_OUT_OF_DISK_SPACE",
		wbemEUnsupportedPutExtension: "WBEM_E_UNSUPPORTED_PUT_EXTENSION",
		wbemEProviderTimedOut:        "WBEM_E_PROVIDER_TIMED_OUT",
		wbemERegistrationTooBroad:    "WBEM_E_REGISTRATION_TOO_BROAD",
	}
	for code, want := range cases {
		require.Contains(t, wbemError(code).Error(), want)
	}
}

func TestWBEMErrorUnknownFallback(t *testing.T) {
	require.Contains(t, wbemError(0xdeadbeef).Error(), "WBEM_E_UNKNOWN")
}

func TestRPCErrorMappingsBroadCoverage(t *testing.T) {
	cases := map[uint32]string{
		rpcAccessDenied:  "ACCESS_DENIED",
		rpcSecPkgError:   "RPC_S_SEC_PKG_ERROR",
		rpcNCaServerBusy: "NCA_S_SERVER_TOO_BUSY",
		0x00000008:       "AUTHENTICATION_TYPE_NOT_RECOGNIZED",
		0x1c00001d:       "NCA_S_UNSUPPORTED_AUTHN_LEVEL",
		0x16c9a041:       "RPC_S_CONNECT_TIMED_OUT",
		0x16c9a11f:       "DCE_CS_C_OK",
		0x16c9a16b:       "RPC_SVC_DESC_LIBIDL",
	}
	for code, want := range cases {
		require.Contains(t, rpcError(code).Error(), want)
	}
}

func TestRPCErrorUnknownFallback(t *testing.T) {
	require.Contains(t, rpcError(0xdeadbeef).Error(), "unknown rpc exception")
}
