//go:build e2e && kerberos

package wmi

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type kerberosE2EConfig struct {
	host       string
	user       string
	pass       string
	realm      string
	kdcHost    string
	kdcPort    int
	krb5Config string
}

func kerberosE2EEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func requireKerberosE2EConfig(t *testing.T) kerberosE2EConfig {
	t.Helper()

	cfg := kerberosE2EConfig{
		host:       os.Getenv("WMI_KRB_HOST"),
		user:       os.Getenv("WMI_USER"),
		pass:       os.Getenv("WMI_PASS"),
		realm:      os.Getenv("WMI_REALM"),
		kdcHost:    os.Getenv("WMI_KDC_HOST"),
		krb5Config: os.Getenv("KRB5_CONFIG"),
	}
	kdcPort := kerberosE2EEnv("WMI_KDC_PORT", "88")
	if cfg.host == "" || cfg.user == "" || cfg.pass == "" || cfg.realm == "" || cfg.kdcHost == "" || cfg.krb5Config == "" {
		t.Skip("Kerberos e2e environment is not configured")
	}

	port, err := strconv.Atoi(kdcPort)
	require.NoError(t, err, "parse WMI_KDC_PORT")
	cfg.kdcPort = port

	info, err := os.Stat(cfg.krb5Config)
	if err != nil || info.IsDir() {
		t.Skipf("Kerberos config %q is not available", cfg.krb5Config)
	}

	return cfg
}

func e2eDialKerberos(t *testing.T, opts ...KerberosOption) *Client {
	t.Helper()

	cfg := requireKerberosE2EConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	opts = append([]KerberosOption{WithKDC(cfg.kdcHost, cfg.kdcPort)}, opts...)
	client, err := DialKerberos(ctx, cfg.host, cfg.user, cfg.pass, cfg.realm, opts...)
	require.NoError(t, err, "DialKerberos")
	t.Cleanup(func() { client.Close() })

	return client
}

func assertE2EOperatingSystemQuery(t *testing.T, client *Client) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rows, err := client.Collect(ctx, "SELECT Caption, Version FROM Win32_OperatingSystem")
	require.NoError(t, err, "Collect")
	require.Len(t, rows, 1, "expected exactly one Win32_OperatingSystem row")

	caption, ok := rows[0]["Caption"]
	require.True(t, ok, "Caption property should exist")
	assert.NotEmpty(t, caption.Value, "Caption value should not be empty")

	version, ok := rows[0]["Version"]
	require.True(t, ok, "Version property should exist")
	assert.NotEmpty(t, version.Value, "Version value should not be empty")
}

func TestE2EDialKerberos(t *testing.T) {
	client := e2eDialKerberos(t)

	require.NotNil(t, client.conn, "expected non-nil connection")
	require.NotNil(t, client.service, "expected non-nil service")
	require.True(t, client.conn.isConnected(), "expected connection to be active")
	require.True(t, client.conn.hasValidKeys(), "expected kerberos keys to be cached on the connection")
}

func TestE2EQueryWin32OperatingSystemKerberos(t *testing.T) {
	client := e2eDialKerberos(t)
	assertE2EOperatingSystemQuery(t, client)
}

func TestE2ECollectDecodedProcessesKerberos(t *testing.T) {
	client := e2eDialKerberos(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	type Proc struct {
		Name      string `wmi:"Name"`
		ProcessID uint32 `wmi:"ProcessId"`
	}

	var procs []Proc
	err := client.CollectDecoded(ctx, "SELECT Name, ProcessId FROM Win32_Process", &procs)
	require.NoError(t, err, "CollectDecoded Win32_Process")
	require.Greater(t, len(procs), 0, "expected at least one process")

	foundSystem := false
	for _, p := range procs {
		assert.NotEmpty(t, p.Name, "process name should not be empty")
		if p.Name == "System Idle Process" || p.Name == "System" {
			foundSystem = true
		}
	}
	assert.True(t, foundSystem, "expected to find a System process")
}

func TestE2EKerberosCacheReuse(t *testing.T) {
	cfg := requireKerberosE2EConfig(t)
	cacheFile := filepath.Join(t.TempDir(), "krb-cache.json")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	first, err := DialKerberos(
		ctx,
		cfg.host,
		cfg.user,
		cfg.pass,
		cfg.realm,
		WithKDC(cfg.kdcHost, cfg.kdcPort),
		WithKerberosCache(NewKerberosCache(cacheFile)),
	)
	require.NoError(t, err, "first DialKerberos")
	require.NoError(t, first.Close())

	cache := NewKerberosCache(cacheFile)
	require.True(t, cache.HasValidKeys(), "expected persisted kerberos cache to contain valid keys")

	second, err := DialKerberos(
		ctx,
		cfg.host,
		cfg.user,
		"definitely-wrong-password",
		cfg.realm,
		WithKDC(cfg.kdcHost, cfg.kdcPort),
		WithKerberosCache(cache),
	)
	require.NoError(t, err, "expected cached TGS to allow a second dial")
	t.Cleanup(func() { second.Close() })

	assertE2EOperatingSystemQuery(t, second)
}
