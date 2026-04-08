package wmi

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWithConnectTimeoutAppliesToNTLMAndKerberos(t *testing.T) {
	timeout := 5 * time.Second

	var ntlmOpt NTLMOption = WithConnectTimeout(timeout)
	var kerberosOpt KerberosOption = WithConnectTimeout(timeout)

	var ntlmCfg ntlmConfig
	ntlmOpt.applyNTLM(&ntlmCfg)
	require.Equal(t, timeout, ntlmCfg.connectTimeout)

	var kerberosCfg kerberosConfig
	kerberosOpt.applyKerberos(&kerberosCfg)
	require.Equal(t, timeout, kerberosCfg.connectTimeout)
}

func TestWithConnectTimeoutPreservesEarlierParentDeadline(t *testing.T) {
	parentTimeout := 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), parentTimeout)
	defer cancel()

	derived, derivedCancel := withConnectTimeout(ctx, time.Second)
	defer derivedCancel()

	parentDeadline, ok := ctx.Deadline()
	require.True(t, ok)
	derivedDeadline, ok := derived.Deadline()
	require.True(t, ok)
	require.True(t, derivedDeadline.Equal(parentDeadline), "derived deadline should not extend parent deadline")
}

func TestWithConnectTimeoutSetsDeadlineWhenParentHasNone(t *testing.T) {
	timeout := 100 * time.Millisecond

	derived, cancel := withConnectTimeout(context.Background(), timeout)
	defer cancel()

	deadline, ok := derived.Deadline()
	require.True(t, ok)
	require.WithinDuration(t, time.Now().Add(timeout), deadline, 50*time.Millisecond)
}

func TestWithConnectTimeoutNoopForNonPositiveDuration(t *testing.T) {
	ctx := context.Background()

	derived, cancel := withConnectTimeout(ctx, 0)
	defer cancel()

	require.Equal(t, ctx, derived)
}
