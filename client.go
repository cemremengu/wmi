package wmi

import (
	"context"
	"iter"
	"time"
)

// Client is a high-level WMI client that owns both the connection and the
// authenticated service. Create one with [DialNTLM] or [DialKerberos]:
//
//	client, err := wmi.DialNTLM(ctx, "10.0.0.1", "admin", "secret")
//	if err != nil { log.Fatal(err) }
//	defer client.Close()
type Client struct {
	conn    *connection
	service *service
}

// NTLMOption configures [DialNTLM].
type NTLMOption interface {
	applyNTLM(*ntlmConfig)
}

// KerberosOption configures [DialKerberos].
type KerberosOption interface {
	applyKerberos(*kerberosConfig)
}

// DialOption configures connection setup shared by [DialNTLM] and
// [DialKerberos].
type DialOption interface {
	NTLMOption
	KerberosOption
}

type ntlmOptionFunc func(*ntlmConfig)

func (f ntlmOptionFunc) applyNTLM(c *ntlmConfig) { f(c) }

type kerberosOptionFunc func(*kerberosConfig)

func (f kerberosOptionFunc) applyKerberos(c *kerberosConfig) { f(c) }

type connectTimeoutOption time.Duration

func (o connectTimeoutOption) applyNTLM(c *ntlmConfig) {
	c.connectTimeout = time.Duration(o)
}

func (o connectTimeoutOption) applyKerberos(c *kerberosConfig) {
	c.connectTimeout = time.Duration(o)
}

type dialConfig struct {
	connectTimeout time.Duration
}

type ntlmConfig struct {
	dialConfig
	domain string
}

// WithDomain sets the domain for NTLM authentication.
func WithDomain(domain string) NTLMOption {
	return ntlmOptionFunc(func(c *ntlmConfig) { c.domain = domain })
}

type kerberosConfig struct {
	dialConfig
	kdcHost string
	kdcPort int
	cache   *KerberosCache
}

// WithConnectTimeout sets a timeout for the overall dial and authentication
// handshake. The caller's context is still honored and can cancel earlier.
func WithConnectTimeout(timeout time.Duration) DialOption {
	return connectTimeoutOption(timeout)
}

// WithKDC overrides the Kerberos KDC host and port.
// By default DialKerberos uses the target host on port 88.
func WithKDC(host string, port int) KerberosOption {
	return kerberosOptionFunc(func(c *kerberosConfig) {
		c.kdcHost = host
		c.kdcPort = port
	})
}

// WithKerberosCache sets a custom Kerberos ticket cache.
func WithKerberosCache(cache *KerberosCache) KerberosOption {
	return kerberosOptionFunc(func(c *kerberosConfig) { c.cache = cache })
}

// DialNTLM connects to host and authenticates using NTLM, returning a
// ready-to-use [Client]. Call [Client.Close] when done.
//
//	client, err := wmi.DialNTLM(ctx, "10.0.0.1", "admin", "secret")
//	client, err := wmi.DialNTLM(ctx, host, user, pass, wmi.WithDomain("CORP"))
func DialNTLM(ctx context.Context, host, username, password string, opts ...NTLMOption) (*Client, error) {
	var cfg ntlmConfig
	for _, o := range opts {
		o.applyNTLM(&cfg)
	}
	ctx, cancel := withConnectTimeout(ctx, cfg.connectTimeout)
	defer cancel()
	conn := newConnection(host, username, password)
	conn.domain = cfg.domain
	svc, err := conn.negotiateNTLM(ctx)
	if err != nil {
		conn.close()
		return nil, err
	}
	return &Client{conn: conn, service: svc}, nil
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
		o.applyKerberos(&cfg)
	}
	ctx, cancel := withConnectTimeout(ctx, cfg.connectTimeout)
	defer cancel()
	conn := newConnection(host, username, password)
	conn.domain = domain
	if cfg.kdcHost != "" {
		conn.kdcHost = cfg.kdcHost
		conn.kdcPort = cfg.kdcPort
	}
	if cfg.cache != nil {
		conn.setKerberosCache(cfg.cache)
	}
	svc, err := conn.negotiateKerberos(ctx)
	if err != nil {
		conn.close()
		return nil, err
	}
	return &Client{conn: conn, service: svc}, nil
}

func withConnectTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

// Close releases the service binding and the underlying connection.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}

	var svcErr error
	if c.service != nil {
		svcErr = c.service.close()
	}

	var connErr error
	if c.conn != nil {
		connErr = c.conn.close()
	}

	if svcErr != nil {
		return svcErr
	}
	return connErr
}

// Query creates a [QContext] bound to this client's connection and service.
//
//	qc := client.Query("SELECT Name FROM Win32_Process", WithTimeout(120))
func (c *Client) Query(wql string, opts ...QueryOption) *QContext {
	return NewQuery(wql, opts...).context(c.conn, c.service)
}

// Collect executes wql and returns all result rows in a slice.
//
//	rows, err := client.Collect(ctx, "SELECT Name FROM Win32_Process", WithTimeout(120))
func (c *Client) Collect(ctx context.Context, wql string, opts ...QueryOption) ([]map[string]*Property, error) {
	return c.Query(wql, opts...).Collect(ctx)
}

// CollectDecoded executes wql and decodes all result rows into dest, which
// must be a non-nil pointer to a slice of structs (or pointers to structs).
//
//	type Proc struct{ Name string `wmi:"Name"` }
//	var procs []Proc
//	err := client.CollectDecoded(ctx, "SELECT Name FROM Win32_Process", &procs, WithTimeout(120))
func (c *Client) CollectDecoded(ctx context.Context, wql string, dest any, opts ...QueryOption) error {
	rows, err := c.Collect(ctx, wql, opts...)
	if err != nil {
		return err
	}
	return DecodeAll(rows, dest)
}

// Each executes wql and returns an iterator over the result rows.
// Iteration stops on the first error; break out of the range loop
// to release resources early.
//
//	for props, err := range client.Each(ctx, "SELECT * FROM Win32_Process", WithTimeout(120)) {
//	    if err != nil { ... }
//	    fmt.Println(props["Name"].Value)
//	}
func (c *Client) Each(ctx context.Context, wql string, opts ...QueryOption) iter.Seq2[map[string]*Property, error] {
	return c.Query(wql, opts...).Each(ctx)
}
