package wmi

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewClientWrapsConnAndService(t *testing.T) {
	conn := NewConnection("host", "user", "pass")
	service := &Service{}
	c := NewClient(conn, service)

	require.Same(t, conn, c.Conn)
	require.Same(t, service, c.Service)
}

func TestClientCloseHandlesNils(t *testing.T) {
	c := NewClient(
		NewConnection("host", "user", "pass"),
		&Service{},
	)
	require.NoError(t, c.Close())
}

func TestClientQueryCreatesQContext(t *testing.T) {
	conn := NewConnection("host", "user", "pass")
	service := &Service{}
	c := NewClient(conn, service)

	qc := c.Query("SELECT * FROM Win32_Process")
	require.Equal(t, "SELECT * FROM Win32_Process", qc.query.Query)
	require.Same(t, conn, qc.conn)
	require.Same(t, service, qc.service)
}
