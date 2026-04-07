# wmi

[![CI](https://github.com/cemremengu/wmi/actions/workflows/ci.yml/badge.svg)](https://github.com/cemremengu/wmi/actions/workflows/ci.yml)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/cemremengu/wmi)](https://pkg.go.dev/github.com/cemremengu/wmi)
[![Go Report Card](https://goreportcard.com/badge/github.com/cemremengu/wmi)](https://goreportcard.com/report/github.com/cemremengu/wmi)

Pure Go cross-platform WMI client. Query remote Windows hosts from Linux or Windows over DCOM/RPC using NTLM v2 or Kerberos, no CGo or COM dependencies

**Supports:**
- [x] NTLM v2 authentication (with ESS, key exchange, sealing/signing)                                                                                           
- [x] Kerberos authentication (TGT, TGS, AP-REQ, AES-128/256, RC4, GSS-API wrapping)
- [x] Kerberos ticket caching (file + memory)
- [x] WQL query execution (IWbemServices::ExecQuery)
- [x] Smart enumeration optimization (IWbemFetchSmartEnum)
- [x] Fallback to standard enumeration (IEnumWbemClassObject::Next)
- [x] CIM type decoding (scalars, arrays, references, datetime; `object` type not yet supported)
- [x] Property qualifier loading
- [x] Reference property resolution
- [x] RPC fault handling
- [x] DCOM/NDR encoding and object activation

**Todo:**
- [ ] IWbemServices_ExecQueryAsync (async WMI queries)
- [ ] WMI method invocation (ExecMethod)
- [ ] ExecNotificationQuery (event subscriptions)

## Usage

Below is a complete example of connecting to a remote host with NTLM authentication and querying with the high-level `Client` API. See the `examples/` directory for more.

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/cemremengu/wmi"
)

type OperatingSystem struct {
	Caption string // `wmi:"Caption"`
	Version string // `wmi:"Version"`
}

func main() {
	ctx := context.Background()

	client, err := wmi.DialNTLM(ctx, "10.0.0.1", "username", "password",
		wmi.WithDomain("CORP"), // optional
	)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	var systems []OperatingSystem
	if err := client.CollectDecoded(ctx, "SELECT Caption, Version FROM Win32_OperatingSystem", &systems); err != nil {
		log.Fatal(err)
	}

	for _, os := range systems {
		fmt.Printf("Caption=%s Version=%s\n", os.Caption, os.Version)
	}
}
```

## Kerberos

For Kerberos authentication, use a FQDN as the hostname. Domain is required.
The KDC defaults to the target host on port 88; use `WithKDC` when the
Key Distribution Center is on a separate machine.

```go
client, err := wmi.DialKerberos(ctx, "host.example.com", username, password, "EXAMPLE.COM",
    wmi.WithKDC("kdc.example.com", 88),           // optional: override KDC
    wmi.WithKerberosCache(myCache),                // optional: custom ticket cache
)
if err != nil {
    log.Fatal(err)
}
defer client.Close()
```

Kerberos tickets (TGT + TGS) are cached inside each connection for its
lifetime, so multiple queries reuse them automatically. Use
`WithKerberosCache` with a file-backed cache (`NewKerberosCache(path)`)
to persist tickets to disk across process restarts.

### Advanced connection management

For full control over connection lifecycle, you can use the lower-level API directly:

```go
conn := wmi.NewConnection(host, username, password)
conn.Domain = "EXAMPLE.COM"
service, err := conn.NegotiateKerberos(ctx)
if err != nil { 
	conn.Close()
	log.Fatal(err) 
}
client := wmi.NewClient(conn, service)
defer client.Close()
```

`conn.IsConnected()` reports whether the base DCOM connection is open, and
`conn.HasValidKeys()` reports whether the current Kerberos cache still has
usable tickets.

## Debug logging

The package exposes opt-in debug logging for the DCOM/RPC authentication and
request path. Logging is disabled by default.

Enable the built-in logger:

```go
wmi.EnableDebug()
```

Or attach your own `slog` logger:

```go
logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
	Level: slog.LevelDebug,
}))

wmi.SetLogger(logger.With("component", "wmi"))
wmi.EnableDebug()
```

You can also enable debugging with the `WMI_DEBUG=1` environment variable if
you do not call `wmi.SetDebug`, `wmi.EnableDebug`, or `wmi.DisableDebug`.

Debug configuration is intended to be set during process startup, before you
start using the package from multiple goroutines.

## Query options

High-level API:

- `(*Client).Query(wql)` creates a query context bound to the client.
- `(*Client).Collect(ctx, wql)` executes and returns all rows.
- `(*Client).CollectDecoded(ctx, wql, dest)` executes and decodes all rows into `dest`.
- `(*Client).Each(ctx, wql)` returns an iterator for streaming rows.

Low-level/advanced API:

- `(*QContext).Run(ctx, fn)` executes a callback with a live query context and always releases the remote query handle on return.
- `(*QContext).Results(ctx, fn, options...)` streams each row into `fn` until end-of-results (`WBEM_S_FALSE`).
- `(*QContext).Collect(ctx, options...)` executes and returns all rows for advanced/custom query contexts.
- `(*QContext).Each(ctx)` returns an iterator for streaming rows from an advanced/custom query context.
- `(*QContext).SetResultOptions(...)` configures default property shaping for `Results`, `Collect`, and `Each`.
- `(*QContext).SetFlags(...)` overrides query flags.
- `(*QContext).SetTimeout(...)` sets the default per-row fetch timeout (milliseconds, passed to the WMI protocol).
- `(*QContext).SetSkipOptimize(true)` disables SmartEnum optimization.
- `(*QContext).IsOptimized()` reports whether SmartEnum optimization is active.

### Advanced querying

For streaming large result sets, custom per-query options, or explicit lifecycle
control, drop down to the `QContext` API via `client.Query()`:

```go
qc := client.Query("SELECT Name, ProcessId FROM Win32_Process").
    SetTimeout(120).
    SetSkipOptimize(true).
    SetResultOptions(wmi.ResultOptions{IgnoreDefaults: true})

err := qc.Run(ctx, func(q *wmi.QContext) error {
    fmt.Println("optimized:", q.IsOptimized())

    return q.Results(ctx, func(props map[string]*wmi.Property) error {
        fmt.Printf("pid=%v name=%v\n", props["ProcessId"].Value, props["Name"].Value)
        return nil
    })
})
if err != nil {
    log.Fatal(err)
}
```

`Run` opens the remote query handle, calls your function, and always releases
the handle on return — even if the callback returns an error. `Results` streams
rows one at a time into the callback, so memory usage stays constant regardless
of result set size.

## Struct decoding

Use `CollectDecoded` for struct slices, or `Decode` with `Each` for per-row decoding:

```go
type OperatingSystem struct {
	Caption string `wmi:"Caption"`
	Version string `wmi:"Version"`
}

var systems []OperatingSystem
if err := client.CollectDecoded(ctx, "SELECT Caption, Version FROM Win32_OperatingSystem", &systems); err != nil {
	log.Fatal(err)
}

for props, err := range client.Each(ctx, "SELECT Caption, Version FROM Win32_OperatingSystem") {
	if err != nil {
		log.Fatal(err)
	}
	var os OperatingSystem
	if err := wmi.Decode(props, &os); err != nil {
		log.Fatal(err)
	}
}
```

`DefaultResultOptions()` defaults to:
`IgnoreDefaults=false`, `IgnoreMissing=false`, `LoadQualifiers=false`.

When a row fetch receives `WBEM_S_TIMEDOUT`, the library retries automatically until
an object arrives or `ctx` is canceled. `WBEMNoWait` remains non-blocking and
still returns `WBEM_S_TIMEDOUT` immediately when no object is ready.

## Query flags

`DefaultQueryFlags()` returns `WBEMFlagReturnImmediately | WBEMFlagForwardOnly`,
which is the recommended setting for most queries. Additional flags from
`constants.go` can be OR-ed in:

| Constant                        | Description                              |
|---------------------------------|------------------------------------------|
| `WBEMFlagReturnImmediately`     | Return control immediately (async-style) |
| `WBEMFlagForwardOnly`           | Forward-only cursor (saves memory)       |
| `WBEMFlagDirectRead`            | Bypass provider cache                    |
| `WBEMFlagUseAmendedQualifiers`  | Include localized qualifiers             |

## Property types

Rows returned by `Client.Collect`, `Client.Each`, `QContext.Collect`, and `QContext.Each` use
`map[string]*Property`. The `Property` struct exposes:

| Field / Method        | Description                                          |
|-----------------------|------------------------------------------------------|
| `Value`               | Decoded Go value (`int8`-`uint64`, `float32/64`, `bool`, `string`, `time.Time`, `time.Duration`, `[]any`) |
| `CIMTypeName()`       | CIM type as a string (`"uint32"`, `"string"`, etc.)   |
| `IsArray()`           | True when the property holds an array                |
| `IsReference()`       | True when the value is a WMI object path             |
| `IsArrayReference()`  | True when the property is an array of references     |
| `GetReference(...)`   | Resolve a reference into its own property map        |
| `GetArrayReferences(...)` | Resolve an array of references into property maps |
| `NullDefault`         | True when the value is the null/default for the class |
| `InheritedDefault`    | True when the value is inherited from a parent class  |

## Error handling

All errors satisfy the standard `error` interface. WMI-specific errors are
returned as `*wmi.Error`, which includes the HRESULT `Code`, an optional
operation name `Op`, and a human-readable `Msg`:

```go
var wmiErr *wmi.Error
if errors.As(err, &wmiErr) {
    fmt.Printf("WMI error 0x%08x: %s\n", wmiErr.Code, wmiErr.Msg)
}
```

WBEM and RPC status names use a broad built-in taxonomy. Unknown WBEM codes
fall back to `WBEM_E_UNKNOWN`; unknown RPC codes fall back to
`unknown rpc exception`.

Sentinel errors:

| Variable                   | Meaning                                         |
|----------------------------|-------------------------------------------------|
| `wmi.ErrServerNotOptimized`| Server does not support SmartEnum; library falls back to standard enumeration |
| `wmi.ErrLegacyEncoding`    | Legacy object encoding encountered (unsupported)|
| `wmi.ErrNotImplemented`    | Feature not yet implemented                     |

## Disclaimer

This library was built with significant help from Claude and Codex and may include inaccuracies, inefficient code patterns, or potential security vulnerabilities. Please use it with caution. If you encounter any issues, feel free to open an issue or submit a pull request.
