package wmi

import (
	"context"
	"iter"
)

// Client is a high-level WMI client that owns both the connection and the
// authenticated service. The easiest way to create one is [DialNTLM] or
// [DialKerberos]:
//
//	client, err := wmi.DialNTLM(ctx, "10.0.0.1", "admin", "secret")
//	if err != nil { log.Fatal(err) }
//	defer client.Close()
//
// For advanced use cases, create one with [NewClient] after connecting and
// negotiating authentication explicitly.
type Client struct {
	Conn    *Connection
	Service *Service
}

// NTLMOption configures [DialNTLM].
type NTLMOption func(*ntlmConfig)

type ntlmConfig struct {
	domain string
}

// WithDomain sets the domain for NTLM authentication.
func WithDomain(domain string) NTLMOption {
	return func(c *ntlmConfig) { c.domain = domain }
}

// KerberosOption configures [DialKerberos].
type KerberosOption func(*kerberosConfig)

type kerberosConfig struct {
	kdcHost string
	kdcPort int
	cache   *KerberosCache
}

// WithKDC overrides the Kerberos KDC host and port.
// By default DialKerberos uses the target host on port 88.
func WithKDC(host string, port int) KerberosOption {
	return func(c *kerberosConfig) {
		c.kdcHost = host
		c.kdcPort = port
	}
}

// WithKerberosCache sets a custom Kerberos ticket cache.
func WithKerberosCache(cache *KerberosCache) KerberosOption {
	return func(c *kerberosConfig) { c.cache = cache }
}

// DialNTLM connects to host and authenticates using NTLM, returning a
// ready-to-use [Client]. Call [Client.Close] when done.
//
//	client, err := wmi.DialNTLM(ctx, "10.0.0.1", "admin", "secret")
//	client, err := wmi.DialNTLM(ctx, host, user, pass, wmi.WithDomain("CORP"))
func DialNTLM(ctx context.Context, host, username, password string, opts ...NTLMOption) (*Client, error) {
	var cfg ntlmConfig
	for _, o := range opts {
		o(&cfg)
	}
	conn := NewConnection(host, username, password)
	conn.Domain = cfg.domain
	service, err := conn.NegotiateNTLM(ctx)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &Client{Conn: conn, Service: service}, nil
}

// DialKerberos connects to host and authenticates using Kerberos, returning a
// ready-to-use [Client]. Domain is required. Call [Client.Close] when done.
//
//	client, err := wmi.DialKerberos(ctx, "host.example.com", "admin", "secret", "EXAMPLE.COM")
//	client, err := wmi.DialKerberos(ctx, host, user, pass, domain, wmi.WithKDC("kdc.host", 88))
func DialKerberos(
	ctx context.Context,
	host, username, password, domain string,
	opts ...KerberosOption,
) (*Client, error) {
	var cfg kerberosConfig
	for _, o := range opts {
		o(&cfg)
	}
	conn := NewConnection(host, username, password)
	conn.Domain = domain
	if cfg.kdcHost != "" {
		conn.KDCHost = cfg.kdcHost
		conn.KDCPort = cfg.kdcPort
	}
	if cfg.cache != nil {
		conn.SetKerberosCache(cfg.cache)
	}
	service, err := conn.NegotiateKerberos(ctx)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &Client{Conn: conn, Service: service}, nil
}

// NewClient wraps an established connection and authenticated service into
// a Client. The caller is responsible for having already called
// [Connection.Connect] and one of the Negotiate methods.
//
// For most use cases, prefer [DialNTLM] or [DialKerberos] instead.
func NewClient(conn *Connection, service *Service) *Client {
	return &Client{Conn: conn, Service: service}
}

// Close releases the service binding and the underlying connection.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}

	var svcErr error
	if c.Service != nil {
		svcErr = c.Service.Close()
	}

	var connErr error
	if c.Conn != nil {
		connErr = c.Conn.Close()
	}

	if svcErr != nil {
		return svcErr
	}
	return connErr
}

// Query creates a [QContext] bound to this client's connection and service.
//
//	qc := client.Query("SELECT Name FROM Win32_Process")
func (c *Client) Query(wql string) *QContext {
	return NewQuery(wql).Context(c.Conn, c.Service)
}

// Collect executes wql and returns all result rows in a slice.
//
//	rows, err := client.Collect(ctx, "SELECT Name FROM Win32_Process")
func (c *Client) Collect(ctx context.Context, wql string) ([]map[string]*Property, error) {
	return c.Query(wql).Collect(ctx)
}

// CollectDecoded executes wql and decodes all result rows into dest, which
// must be a non-nil pointer to a slice of structs (or pointers to structs).
//
//	type Proc struct{ Name string `wmi:"Name"` }
//	var procs []Proc
//	err := client.CollectDecoded(ctx, "SELECT Name FROM Win32_Process", &procs)
func (c *Client) CollectDecoded(ctx context.Context, wql string, dest any) error {
	rows, err := c.Collect(ctx, wql)
	if err != nil {
		return err
	}
	return DecodeAll(rows, dest)
}

// Each executes wql and returns an iterator over the result rows.
// Iteration stops on the first error; break out of the range loop
// to release resources early.
//
//	for props, err := range client.Each(ctx, "SELECT * FROM Win32_Process") {
//	    if err != nil { ... }
//	    fmt.Println(props["Name"].Value)
//	}
func (c *Client) Each(ctx context.Context, wql string) iter.Seq2[map[string]*Property, error] {
	return c.Query(wql).Each(ctx)
}
