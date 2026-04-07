package wmi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// KerberosCache holds cached Kerberos TGT and TGS ticket material.
type KerberosCache struct {
	filePath   string
	asRepBytes []byte
	baseKey    []byte
	ticket     []byte
	serviceKey []byte
	etype      int
	expiresAt  time.Time
}

type kerberosCacheDump struct {
	ASRepBytes []byte    `json:"as_rep_bytes"`
	BaseKey    []byte    `json:"base_key"`
	Ticket     []byte    `json:"ticket"`
	ServiceKey []byte    `json:"service_key"`
	EType      int       `json:"etype"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// NewKerberosCache creates a new KerberosCache backed by the given file path.
func NewKerberosCache(filePath string) *KerberosCache {
	return &KerberosCache{filePath: filePath}
}

// FilePath returns the file path of the cache, or empty if in-memory only.
func (k *KerberosCache) FilePath() string {
	if k == nil {
		return ""
	}
	return k.filePath
}

// Load reads cached ticket data from the file on disk.
func (k *KerberosCache) Load() error {
	if k == nil || k.filePath == "" {
		return nil
	}
	data, err := os.ReadFile(k.filePath)
	if err != nil {
		return err
	}
	var dump kerberosCacheDump
	if err := json.Unmarshal(data, &dump); err != nil {
		return err
	}
	k.asRepBytes = append([]byte(nil), dump.ASRepBytes...)
	k.baseKey = append([]byte(nil), dump.BaseKey...)
	k.ticket = append([]byte(nil), dump.Ticket...)
	k.serviceKey = append([]byte(nil), dump.ServiceKey...)
	k.etype = dump.EType
	k.expiresAt = dump.ExpiresAt
	return nil
}

// Save persists the current ticket data to disk.
func (k *KerberosCache) Save() error {
	if k == nil || k.filePath == "" {
		return nil
	}
	dir := filepath.Dir(k.filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	data, err := json.Marshal(kerberosCacheDump{
		ASRepBytes: append([]byte(nil), k.asRepBytes...),
		BaseKey:    append([]byte(nil), k.baseKey...),
		Ticket:     append([]byte(nil), k.ticket...),
		ServiceKey: append([]byte(nil), k.serviceKey...),
		EType:      k.etype,
		ExpiresAt:  k.expiresAt,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(k.filePath, data, 0o600)
}

func (k *KerberosCache) ensureLoaded() {
	if k == nil || k.filePath == "" {
		return
	}
	if len(k.asRepBytes) != 0 && len(k.baseKey) != 0 && len(k.ticket) != 0 && len(k.serviceKey) != 0 &&
		!k.expiresAt.IsZero() {
		return
	}
	_ = k.Load()
}

func (k *KerberosCache) setTGT(asRepBytes, baseKey []byte) {
	if k == nil {
		return
	}
	k.asRepBytes = append([]byte(nil), asRepBytes...)
	k.baseKey = append([]byte(nil), baseKey...)
}

func (k *KerberosCache) setTGS(ticket, serviceKey []byte, etype int, expiresAt time.Time) {
	if k == nil {
		return
	}
	k.ticket = append([]byte(nil), ticket...)
	k.serviceKey = append([]byte(nil), serviceKey...)
	k.etype = etype
	k.expiresAt = expiresAt
}

// HasValidKeys reports whether the cached keys are present and not yet expired.
func (k *KerberosCache) HasValidKeys(offset ...time.Duration) bool {
	if k == nil || len(k.asRepBytes) == 0 || len(k.baseKey) == 0 || len(k.ticket) == 0 || len(k.serviceKey) == 0 ||
		k.expiresAt.IsZero() {
		k.ensureLoaded()
	}
	if k == nil || len(k.asRepBytes) == 0 || len(k.baseKey) == 0 || len(k.ticket) == 0 || len(k.serviceKey) == 0 ||
		k.expiresAt.IsZero() {
		return false
	}
	window := 90 * time.Second
	if len(offset) > 0 {
		window = offset[0]
	}
	return time.Now().Before(k.expiresAt.Add(-window))
}

func (k *KerberosCache) hasValidKeys(offset time.Duration) bool {
	return k.HasValidKeys(offset)
}
