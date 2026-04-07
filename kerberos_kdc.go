package wmi

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

func sendKerberosPacket(ctx context.Context, packet []byte, host string, port int) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	wire := make([]byte, 4+len(packet))
	wireLen, err := checkedUint32(len(packet))
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(wire[:4], wireLen)
	copy(wire[4:], packet)
	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	respLen := binary.BigEndian.Uint32(header)
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}
