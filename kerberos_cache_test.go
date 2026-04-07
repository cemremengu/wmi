package wmi

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestKerberosCacheSaveLoad(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "krb-cache.json")
	expiresAt := time.Now().Add(10 * time.Minute).Round(0)

	cache := NewKerberosCache(filePath)
	cache.setTGT([]byte("as-rep"), []byte("base-key"))
	cache.setTGS([]byte("ticket"), []byte("service-key"), 18, expiresAt)
	require.NoError(t, cache.Save())

	loaded := NewKerberosCache(filePath)
	require.True(t, loaded.HasValidKeys(), "expected persisted cache to load valid keys")
	require.Equal(t, []byte("as-rep"), loaded.asRepBytes)
	require.Equal(t, []byte("base-key"), loaded.baseKey)
	require.Equal(t, []byte("ticket"), loaded.ticket)
	require.Equal(t, []byte("service-key"), loaded.serviceKey)
	require.Equal(t, 18, loaded.etype)
	require.True(t, loaded.expiresAt.Equal(expiresAt), "unexpected expiry: got %s want %s", loaded.expiresAt, expiresAt)
}

func TestConnectionCacheHelpers(t *testing.T) {
	conn := newConnection("host.example.com", "alice", "secret")
	require.False(t, conn.isConnected(), "new connection should not be connected")
	require.False(t, conn.hasValidKeys(), "new connection should not have valid kerberos keys")

	filePath := filepath.Join(t.TempDir(), "krb-cache.json")
	cache := NewKerberosCache(filePath)
	cache.setTGT([]byte("as-rep"), []byte("base-key"))
	cache.setTGS([]byte("ticket"), []byte("service-key"), 23, time.Now().Add(5*time.Minute))
	require.NoError(t, cache.Save())

	conn.setKerberosCacheFile(filePath)
	require.True(t, conn.hasValidKeys(), "expected connection to pick up persisted kerberos cache")
}
