package infratrap

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ServePostgresTrap accepts PostgreSQL wire protocol connections, negotiates SSLRequest ('N'),
// captures StartupMessage parameters + cleartext password, records telemetry, and returns SQLSTATE 28P01.
func ServePostgresTrap(ctx context.Context, ln net.Listener, nodeID string, listenPort uint32, emit EventSink) error {
	if listenPort == 0 {
		listenPort = 5432
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go handlePostgresConn(conn, nodeID, listenPort, emit)
	}
}

func handlePostgresConn(conn net.Conn, nodeID string, listenPort uint32, emit EventSink) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	params, err := readPGStartupPacket(conn)
	if err != nil {
		return
	}
	// Request cleartext password: 'R', len=8, authType=3
	_, _ = conn.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 3})

	// Read PasswordMessage ('p', len4, password\0)
	var password string
	var hdr [5]byte
	if _, err := io.ReadFull(conn, hdr[:]); err == nil && hdr[0] == 'p' {
		pLen := int(binary.BigEndian.Uint32(hdr[1:5])) - 4
		if pLen > 0 && pLen <= 4096 {
			pBuf := make([]byte, pLen)
			if _, err := io.ReadFull(conn, pBuf); err == nil {
				password = strings.TrimRight(string(pBuf), "\x00")
			}
		}
	}

	user := params["user"]
	db := params["database"]
	if emit != nil {
		emit(newInfraEvent(nodeID, conn.RemoteAddr().String(), listenPort, "tcp", "postgres", "PG-CRED-PROBE", false, 50, fmt.Sprintf("user=%s db=%s", user, db), "PostgreSQL login probe: user="+user, map[string]any{
			"user":     user,
			"database": db,
			"password": password,
		}, "", ""), nil)
	}

	// Send ErrorResponse ('E') SQLSTATE 28P01
	var errFields bytes.Buffer
	errFields.WriteString("SERROR\x00")
	errFields.WriteString("C28P01\x00")
	errFields.WriteString(fmt.Sprintf("Mpassword authentication failed for user %q\x00", user))
	errFields.WriteByte(0x00)
	var msg bytes.Buffer
	msg.WriteByte('E')
	_ = binary.Write(&msg, binary.BigEndian, int32(4+errFields.Len()))
	msg.Write(errFields.Bytes())
	_, _ = conn.Write(msg.Bytes())
}

func readPGStartupPacket(conn net.Conn) (map[string]string, error) {
	for attempt := 0; attempt < 2; attempt++ {
		var lenBuf [4]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return nil, err
		}
		totalLen := int(binary.BigEndian.Uint32(lenBuf[:]))
		if totalLen < 8 || totalLen > 16*1024 {
			return nil, fmt.Errorf("invalid startup packet len %d", totalLen)
		}
		payload := make([]byte, totalLen-4)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return nil, err
		}
		code := binary.BigEndian.Uint32(payload[:4])
		if code == 80877103 { // SSLRequest
			_, _ = conn.Write([]byte{'N'})
			continue
		}
		params := make(map[string]string)
		kvBytes := bytes.Split(payload[4:], []byte{0x00})
		for i := 0; i+1 < len(kvBytes); i += 2 {
			k := string(kvBytes[i])
			if k == "" {
				break
			}
			params[k] = string(kvBytes[i+1])
		}
		return params, nil
	}
	return nil, fmt.Errorf("too many SSL negotiation packets")
}
