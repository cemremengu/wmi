package wmi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

func sendKerberosPacket(ctx context.Context, packet []byte, host string, port int) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stop()

	wire := make([]byte, 4+len(packet))
	wireLen, err := checkedUint32(len(packet))
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(wire[:4], wireLen)
	copy(wire[4:], packet)
	if _, err := conn.Write(wire); err != nil {
		return nil, kerberosPacketError(ctx, err)
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, kerberosPacketError(ctx, err)
	}
	respLen := binary.BigEndian.Uint32(header)
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, kerberosPacketError(ctx, err)
	}
	return resp, nil
}

func kerberosPacketError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("%w: %w", ctxErr, err)
	}
	var netErr net.Error
	if deadline, ok := ctx.Deadline(); ok && errors.As(err, &netErr) && netErr.Timeout() &&
		!time.Now().Before(deadline) {
		return fmt.Errorf("%w: %w", context.DeadlineExceeded, err)
	}
	return err
}
