package infratrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"
)

// ServeMySQLTrap accepts MySQL TCP wire connections, sends an authentic v10 greeting packet,
// parses HandshakeResponse41 usernames/auth payloads, records telemetry, and responds with error 1045.
func ServeMySQLTrap(ctx context.Context, ln net.Listener, nodeID string, listenPort uint32, emit EventSink) error {
	if listenPort == 0 {
		listenPort = 3306
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
		go handleMySQLConn(conn, nodeID, listenPort, emit)
	}
}

func handleMySQLConn(conn net.Conn, nodeID string, listenPort uint32, emit EventSink) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	salt := make([]byte, 20)
	_, _ = rand.Read(salt)
	greeting := buildMySQLHandshakeV10("8.0.36-0ubuntu0.22.04.1", salt)
	if _, err := conn.Write(greeting); err != nil {
		return
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	pLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if pLen <= 0 || pLen > 64*1024 {
		return
	}
	body := make([]byte, pLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return
	}

	user := parseMySQLUsername(body)
	if emit != nil {
		emit(newInfraEvent(nodeID, conn.RemoteAddr().String(), listenPort, "tcp", "mysql", "MYSQL-CRED-PROBE", false, 50, fmt.Sprintf("user=%s auth_len=%d", user, len(body)), "MySQL login probe: user="+user, map[string]any{
			"username":     user,
			"auth_hex":     hex.EncodeToString(body),
			"server_salt":  hex.EncodeToString(salt),
		}, "", ""), nil)
	}

	// Send ERR packet (code 1045 Access denied)
	msg := fmt.Sprintf("#28000Access denied for user '%s'@'%s' (using password: YES)", user, conn.RemoteAddr().String())
	errPayload := append([]byte{0xff, 0x15, 0x04}, []byte(msg)...)
	_, _ = conn.Write(frameMySQLPacket(2, errPayload))
}

func buildMySQLHandshakeV10(serverVersion string, salt []byte) []byte {
	var b bytes.Buffer
	b.WriteByte(0x0a) // protocol v10
	b.WriteString(serverVersion)
	b.WriteByte(0x00)
	b.Write([]byte{0x2a, 0x00, 0x00, 0x00}) // thread id
	b.Write(salt[:8])
	b.WriteByte(0x00)
	b.Write([]byte{0xff, 0xf7})             // lower capability flags
	b.WriteByte(0x21)                       // utf8 charset
	b.Write([]byte{0x02, 0x00})             // status flags
	b.Write([]byte{0xff, 0x81})             // upper capability flags
	b.WriteByte(21)                         // auth plugin data len
	b.Write(make([]byte, 10))               // reserved
	b.Write(salt[8:20])
	b.WriteByte(0x00)
	b.WriteString("mysql_native_password")
	b.WriteByte(0x00)
	return frameMySQLPacket(0, b.Bytes())
}

func frameMySQLPacket(seq byte, payload []byte) []byte {
	l := len(payload)
	out := make([]byte, 4+l)
	out[0] = byte(l)
	out[1] = byte(l >> 8)
	out[2] = byte(l >> 16)
	out[3] = seq
	copy(out[4:], payload)
	return out
}

func parseMySQLUsername(handshakeResp []byte) string {
	if len(handshakeResp) <= 32 {
		return ""
	}
	rest := handshakeResp[32:]
	if idx := bytes.IndexByte(rest, 0x00); idx >= 0 {
		return string(rest[:idx])
	}
	return string(rest)
}
