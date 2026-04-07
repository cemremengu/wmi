//go:build e2e

package wmi

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func e2eEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func e2eConnect(t *testing.T) (*Connection, *Service) {
	t.Helper()

	host := e2eEnv("WMI_HOST", "localhost")
	user := e2eEnv("WMI_USER", "wmitest")
	pass := e2eEnv("WMI_PASS", "P@ssw0rd!23")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	conn := NewConnection(host, user, pass)

	require.NoError(t, conn.Connect(ctx), "connect")
	t.Cleanup(func() { conn.Close() })

	service, err := conn.NegotiateNTLM(ctx)
	require.NoError(t, err, "negotiate ntlm")
	t.Cleanup(func() { service.Close() })

	return conn, service
}

func TestE2ENTLMConnect(t *testing.T) {
	conn, service := e2eConnect(t)

	require.True(t, conn.IsConnected(), "expected connection to be active after NegotiateNTLM")
	_ = service
}

func TestE2EQueryWin32OperatingSystem(t *testing.T) {
	conn, service := e2eConnect(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var count int
	query := NewQuery("SELECT Caption, Version FROM Win32_OperatingSystem")
	for props, err := range query.Context(conn, service).Each(ctx) {
		require.NoError(t, err, "query Win32_OperatingSystem")
		count++
		caption, ok := props["Caption"]
		if !ok {
			assert.Fail(t, "Caption property missing from Win32_OperatingSystem")
			continue
		}
		assert.NotEmpty(t, caption.Value, "Caption is empty")
	}
	require.Greater(t, count, 0, "expected at least one Win32_OperatingSystem result")
}

func TestE2EQueryWin32Process(t *testing.T) {
	conn, service := e2eConnect(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var count int
	query := NewQuery("SELECT Name, ProcessId FROM Win32_Process")
	for _, err := range query.Context(conn, service).Each(ctx) {
		require.NoError(t, err, "query Win32_Process")
		count++
	}
	require.Greater(t, count, 0, "expected at least one Win32_Process result")
}

func TestE2EInvalidQuery(t *testing.T) {
	conn, service := e2eConnect(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	query := NewQuery("SELECT * FROM FakeNonExistentClass")
	var gotErr error
	for _, err := range query.Context(conn, service).Each(ctx) {
		gotErr = err
		break
	}
	require.Error(t, gotErr, "expected an error for invalid WMI class query")
}

// --- DialNTLM convenience API tests ---

func e2eDialNTLM(t *testing.T) *Client {
	t.Helper()

	host := e2eEnv("WMI_HOST", "localhost")
	user := e2eEnv("WMI_USER", "wmitest")
	pass := e2eEnv("WMI_PASS", "P@ssw0rd!23")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	client, err := DialNTLM(ctx, host, user, pass)
	require.NoError(t, err, "DialNTLM")
	t.Cleanup(func() { client.Close() })

	return client
}

func TestE2EDialNTLM(t *testing.T) {
	client := e2eDialNTLM(t)

	require.NotNil(t, client.Conn, "expected non-nil connection")
	require.NotNil(t, client.Service, "expected non-nil service")
	require.True(t, client.Conn.IsConnected(), "expected connection to be active")
}

func TestE2ECollectDecoded(t *testing.T) {
	client := e2eDialNTLM(t)

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

func TestE2ECollectDecodedProcesses(t *testing.T) {
	client := e2eDialNTLM(t)

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

func TestE2ECollect(t *testing.T) {
	client := e2eDialNTLM(t)

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

func TestE2EEach(t *testing.T) {
	client := e2eDialNTLM(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var count int
	for props, err := range client.Each(ctx, "SELECT Name, ProcessId FROM Win32_Process") {
		require.NoError(t, err, "Each iteration error")
		name, ok := props["Name"]
		assert.True(t, ok, "Name property should exist")
		if ok {
			assert.NotNil(t, name.Value, "Name value should not be nil")
		}
		count++
	}
	require.Greater(t, count, 0, "expected at least one process from Each")
}

func TestE2EEachBreakEarly(t *testing.T) {
	client := e2eDialNTLM(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var count int
	for _, err := range client.Each(ctx, "SELECT Name FROM Win32_Process") {
		require.NoError(t, err)
		count++
		if count >= 3 {
			break
		}
	}
	assert.Equal(t, 3, count, "expected exactly 3 rows after early break")
}

func TestE2ECollectDecodedInvalidQuery(t *testing.T) {
	client := e2eDialNTLM(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	type Dummy struct {
		Name string `wmi:"Name"`
	}

	var results []Dummy
	err := client.CollectDecoded(ctx, "SELECT * FROM FakeNonExistentClass", &results)
	require.Error(t, err, "expected error for invalid WMI class")
}

func TestE2ECollectDecodedDateTime(t *testing.T) {
	client := e2eDialNTLM(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	type OS struct {
		Caption        string    `wmi:"Caption"`
		LastBootUpTime time.Time `wmi:"LastBootUpTime"`
	}

	var results []OS
	err := client.CollectDecoded(ctx, "SELECT Caption, LastBootUpTime FROM Win32_OperatingSystem", &results)
	require.NoError(t, err, "CollectDecoded with datetime")
	require.Len(t, results, 1)
	assert.False(t, results[0].LastBootUpTime.IsZero(), "LastBootUpTime should not be zero")
}

func TestE2ECollectDecodedNoTags(t *testing.T) {
	client := e2eDialNTLM(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Field names match WMI property names exactly — no struct tags needed.
	type OS struct {
		Caption string
		Version string
	}

	var results []OS
	err := client.CollectDecoded(ctx, "SELECT Caption, Version FROM Win32_OperatingSystem", &results)
	require.NoError(t, err, "CollectDecoded without struct tags")
	require.Len(t, results, 1)
	assert.NotEmpty(t, results[0].Caption, "Caption should not be empty")
	assert.NotEmpty(t, results[0].Version, "Version should not be empty")
}

func TestE2ECollectDecodedNoTagsProcess(t *testing.T) {
	client := e2eDialNTLM(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	type Proc struct {
		Name      string
		ProcessId uint32
	}

	var procs []Proc
	err := client.CollectDecoded(ctx, "SELECT Name, ProcessId FROM Win32_Process", &procs)
	require.NoError(t, err, "CollectDecoded without tags Win32_Process")
	require.Greater(t, len(procs), 0, "expected at least one process")
	for _, p := range procs {
		assert.NotEmpty(t, p.Name, "process name should not be empty")
	}
}
