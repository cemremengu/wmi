//go:build e2e

package wmi

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func e2eDialKerberos(t *testing.T) *Client {
	t.Helper()

	cfg := loadE2EConfig()
	if cfg.realm == "" {
		t.Skip("WMI_REALM is required for Kerberos e2e tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	client, err := DialKerberos(ctx, cfg.host, cfg.user, cfg.pass, cfg.realm, WithKDC(cfg.kdcHost, cfg.kdcPort))
	require.NoError(t, err, "DialKerberos")
	t.Cleanup(func() { client.Close() })

	return client
}

func TestE2EDialKerberos(t *testing.T) {
	client := e2eDialKerberos(t)

	require.NotNil(t, client.conn, "expected non-nil connection")
	require.NotNil(t, client.service, "expected non-nil service")
	require.True(t, client.conn.isConnected(), "expected connection to be active")
	require.True(t, client.conn.hasValidKeys(), "expected kerberos cache to contain valid keys")
}

func TestE2EKerberosCollectDecoded(t *testing.T) {
	client := e2eDialKerberos(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	type OS struct {
		Caption string `wmi:"Caption"`
		Version string `wmi:"Version"`
	}

	var results []OS
	err := client.CollectDecoded(ctx, "SELECT Caption, Version FROM Win32_OperatingSystem", &results)
	require.NoError(t, err, "CollectDecoded")
	require.Len(t, results, 1, "expected exactly one Win32_OperatingSystem row")
	assert.NotEmpty(t, results[0].Caption, "Caption should not be empty")
	assert.NotEmpty(t, results[0].Version, "Version should not be empty")
}
