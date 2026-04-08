package wmi

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestKerberosPacketErrorPreservesContextAndOriginalError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := kerberosPacketError(ctx, io.ErrUnexpectedEOF)
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Contains(t, err.Error(), io.ErrUnexpectedEOF.Error())
}

func TestSendKerberosPacketHonorsContextDeadlineDuringRead(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)

		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		time.Sleep(250 * time.Millisecond)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = sendKerberosPacket(ctx, []byte{0x01, 0x02, 0x03}, "127.0.0.1", ln.Addr().(*net.TCPAddr).Port)
	elapsed := time.Since(start)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, elapsed, 200*time.Millisecond)
	<-serverDone
}

func TestSendKerberosPacketHonorsContextCancelDuringRead(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)

		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		time.Sleep(250 * time.Millisecond)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	start := time.Now()
	_, err = sendKerberosPacket(ctx, []byte{0x01, 0x02, 0x03}, "127.0.0.1", ln.Addr().(*net.TCPAddr).Port)
	elapsed := time.Since(start)

	require.ErrorIs(t, err, context.Canceled)
	require.Less(t, elapsed, 200*time.Millisecond)
	<-serverDone
}

func TestSendKerberosPacketAcceptsLargeTCPResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	largeResp := make([]byte, 65537)
	for i := range largeResp {
		largeResp[i] = byte(i)
	}

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)

		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 256)
		_, _ = conn.Read(buf)

		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, uint32(len(largeResp)))
		_, _ = conn.Write(header)
		_, _ = conn.Write(largeResp)
	}()

	resp, err := sendKerberosPacket(
		context.Background(),
		[]byte{0x01, 0x02, 0x03},
		"127.0.0.1",
		ln.Addr().(*net.TCPAddr).Port,
	)

	require.NoError(t, err)
	require.Equal(t, largeResp, resp)
	<-serverDone
}
