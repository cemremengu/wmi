package wmi

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClientCloseHandlesNils(t *testing.T) {
	c := &Client{
		conn:    newConnection("host", "user", "pass"),
		service: &service{},
	}
	require.NoError(t, c.Close())
}

func TestClientQueryCreatesQContext(t *testing.T) {
	conn := newConnection("host", "user", "pass")
	svc := &service{}
	c := &Client{conn: conn, service: svc}

	qc := c.Query("SELECT * FROM Win32_Process")
	require.Equal(t, "SELECT * FROM Win32_Process", qc.query.Query)
	require.Same(t, conn, qc.conn)
	require.Same(t, svc, qc.service)
}
