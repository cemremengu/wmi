package wmi

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

var (
	debugEnabled = envDebugEnabled()
	debugLogger  = slog.New(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}),
	).With("component", "wmi")
)

func envDebugEnabled() bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv("WMI_DEBUG")))
	return v != "" && v != "0" && v != "false" && v != "off" && v != "no"
}

func debugOn() bool {
	return debugEnabled
}

func debugf(format string, args ...any) {
	if debugOn() {
		debugLogger.Debug(fmt.Sprintf(format, args...))
	}
}

func previewHex(data []byte, n int) string {
	if len(data) == 0 {
		return ""
	}
	if n > len(data) {
		n = len(data)
	}
	out := hex.EncodeToString(data[:n])
	if n < len(data) {
		return out + "..."
	}
	return out
}

// SetDebug enables or disables debug logging.
func SetDebug(enabled bool) {
	debugEnabled = enabled
}

// SetLogger replaces the debug logger; pass nil to reset to the default.
func SetLogger(logger *slog.Logger) {
	if logger == nil {
		debugLogger = slog.New(
			slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}),
		).With("component", "wmi")
		return
	}
	debugLogger = logger
}

// EnableDebug is a shorthand for SetDebug(true).
func EnableDebug() {
	SetDebug(true)
}

// DisableDebug is a shorthand for SetDebug(false).
func DisableDebug() {
	SetDebug(false)
}
