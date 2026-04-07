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
- [ ] Kerberos implementation real world (e2e) testing

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
    wmi.WithKerberosCache(myCache),               // optional: custom ticket cache
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

## Querying

The query API exposes four entry points:

- `(*Client).Query(wql, opts...)` creates a reusable query context bound to the client.
- `(*Client).Collect(ctx, wql, opts...)` executes a query and returns all rows.
- `(*Client).CollectDecoded(ctx, wql, dest, opts...)` executes a query and decodes all rows into `dest`.
- `(*Client).Each(ctx, wql, opts...)` returns an iterator for streaming rows.

`(*Client).Query(wql, opts...)` acts as a query builder and returns a `QContext` that can be reused for multiple executions. The returned `QContext` has the same `Collect`, `CollectDecoded`, and `Each` methods, but without the WQL and options parameters since they are already set.

### Query options

Query options can be passed to `(*Client).Query`, `(*Client).Collect`,
`(*Client).CollectDecoded`, and `(*Client).Each`.

Available query options:

- `wmi.WithNamespace(...)` overrides the default `root/cimv2` namespace.
- `wmi.WithLanguage(...)` overrides the query language. The default is `WQL`.
- `wmi.WithFlags(...)` overrides query flags.
- `wmi.WithTimeout(...)` sets the default per-row fetch timeout in milliseconds.
- `wmi.WithSkipOptimize(true)` disables SmartEnum optimization.
- `wmi.WithResultOptions(...)` configures property shaping for results.

Example with a reusable query context:

```go
qc := client.Query(
    "SELECT Name, ProcessId FROM Win32_Process",
    wmi.WithNamespace("root/cimv2"),
    wmi.WithTimeout(120),
    wmi.WithSkipOptimize(true),
    wmi.WithResultOptions(wmi.ResultOptions{IgnoreDefaults: true}),
)

for props, err := range qc.Each(ctx) {
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("pid=%v name=%v\n", props["ProcessId"].Value, props["Name"].Value)
}
```

The same `QContext` can also decode directly into a slice destination:

```go
var processes []struct {
    Name      string `wmi:"Name"`
    ProcessID uint32 `wmi:"ProcessId"`
}

if err := qc.CollectDecoded(ctx, &processes); err != nil {
    log.Fatal(err)
}
```

The same options can be passed directly to other query helpers:

```go
rows, err := client.Collect(
    ctx,
    "SELECT Name FROM Win32_Service",
    wmi.WithNamespace("root/cimv2"),
    wmi.WithTimeout(120),
)
if err != nil {
    log.Fatal(err)
}
```

Querying a non-default namespace works the same way:

```go
events := client.Query(
    "SELECT * FROM __EventFilter",
    wmi.WithNamespace("root/subscription"),
)

rows, err := events.Collect(ctx)
if err != nil {
    log.Fatal(err)
}
```

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
