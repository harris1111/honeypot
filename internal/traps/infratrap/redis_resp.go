package infratrap

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/harris/honeypot/internal/traps/webcve"
)

// ServeRedisRESP runs a native Go RESP2/RESP3 Redis trap supporting AUTH/INFO/CONFIG/SET/SLAVEOF/EVAL
// and CVE-2022-0543 Debian Lua sandbox escape capture without invoking any real Redis or Lua engine.
func ServeRedisRESP(ctx context.Context, ln net.Listener, nodeID string, listenPort uint32, emit EventSink) error {
	if listenPort == 0 {
		listenPort = 6379
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
		go handleRedisConn(ctx, conn, nodeID, listenPort, emit)
	}
}

func handleRedisConn(ctx context.Context, conn net.Conn, nodeID string, listenPort uint32, emit EventSink) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	rd := bufio.NewReaderSize(conn, 64*1024)
	remote := conn.RemoteAddr().String()
	kv := map[string]string{
		"dir":        "/var/lib/redis",
		"dbfilename": "dump.rdb",
	}

	for {
		if ctx.Err() != nil {
			return
		}
		args, err := readRESPCommand(rd)
		if err != nil {
			if err != io.EOF {
				return
			}
			return
		}
		if len(args) == 0 {
			continue
		}
		cmd := strings.ToUpper(args[0])
		joined := strings.Join(args, " ")

		switch cmd {
		case "PING":
			_, _ = conn.Write([]byte("+PONG\r\n"))

		case "QUIT":
			_, _ = conn.Write([]byte("+OK\r\n"))
			return

		case "AUTH":
			_, _ = conn.Write([]byte("+OK\r\n"))
			if emit != nil {
				emit(newInfraEvent(nodeID, remote, listenPort, "tcp", "redis", "REDIS-AUTH", false, 45, joined, "Redis AUTH probe", map[string]any{"args": args[1:]}, "", ""), nil)
			}

		case "INFO":
			infoBody := "# Server\r\nredis_version:6.0.16\r\nos:Linux 5.10.0-21-amd64 x86_64\r\narch_bits:64\r\ntcp_port:6379\r\n"
			_, _ = fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(infoBody), infoBody)

		case "CONFIG":
			if len(args) >= 3 && strings.EqualFold(args[1], "GET") {
				val := kv[strings.ToLower(args[2])]
				_, _ = fmt.Fprintf(conn, "*2\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", len(args[2]), args[2], len(val), val)
			} else if len(args) >= 4 && strings.EqualFold(args[1], "SET") {
				kv[strings.ToLower(args[2])] = args[3]
				_, _ = conn.Write([]byte("+OK\r\n"))
				if emit != nil {
					emit(newInfraEvent(nodeID, remote, listenPort, "tcp", "redis", "REDIS-CONFIG-SET", false, 80, joined, "Redis CONFIG SET persistence attempt", map[string]any{"key": args[2], "value": args[3]}, "", ""), nil)
				}
			} else {
				_, _ = conn.Write([]byte("+OK\r\n"))
			}

		case "SET":
			_, _ = conn.Write([]byte("+OK\r\n"))
			urls := webcve.ExtractHTTPURLs(joined)
			if strings.Contains(joined, "ssh-") || len(urls) > 0 || strings.Contains(joined, "cron") {
				if emit != nil {
					emit(newInfraEvent(nodeID, remote, listenPort, "tcp", "redis", "REDIS-CRON-SSH-DROP", false, 90, joined, "Redis payload SET (cron/SSH/URL)", map[string]any{"urls": urls, "payload": joined}, "", ""), urls)
				}
			}

		case "SLAVEOF", "REPLICAOF":
			_, _ = conn.Write([]byte("+OK\r\n"))
			if emit != nil {
				emit(newInfraEvent(nodeID, remote, listenPort, "tcp", "redis", "REDIS-ROGUE-MASTER", false, 88, joined, "Redis rogue replication attempt", map[string]any{"master": strings.Join(args[1:], ":")}, "", ""), nil)
			}

		case "EVAL", "EVALSHA":
			urls := webcve.ExtractHTTPURLs(joined)
			is0543 := strings.Contains(joined, "package.loadlib") || strings.Contains(joined, "luaopen_io") || strings.Contains(joined, "io.popen")
			cve := "REDIS-EVAL"
			if is0543 {
				cve = "CVE-2022-0543"
			}
			out := "uid=105(redis) gid=110(redis) groups=110(redis)\n"
			_, _ = fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(out), out)
			if emit != nil {
				emit(newInfraEvent(nodeID, remote, listenPort, "tcp", "redis", cve, is0543, 96, joined, "Redis Lua EVAL / CVE-2022-0543 sandbox escape captured", map[string]any{
					"script": joined,
					"urls":   urls,
				}, "", ""), urls)
			}

		case "SAVE", "BGSAVE":
			_, _ = conn.Write([]byte("+OK\r\n"))

		default:
			_, _ = conn.Write([]byte("+OK\r\n"))
		}
	}
}

func readRESPCommand(rd *bufio.Reader) ([]string, error) {
	line, err := rd.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil, nil
	}
	if line[0] != '*' {
		return strings.Fields(line), nil
	}
	count, err := strconv.Atoi(line[1:])
	if err != nil || count < 0 || count > 1024 {
		return nil, fmt.Errorf("invalid resp array length")
	}
	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
		hdr, err := rd.ReadString('\n')
		if err != nil {
			return nil, err
		}
		hdr = strings.TrimRight(hdr, "\r\n")
		if len(hdr) < 2 || hdr[0] != '$' {
			return nil, fmt.Errorf("expected bulk string")
		}
		n, err := strconv.Atoi(hdr[1:])
		if err != nil || n < 0 || n > 1024*1024 {
			return nil, fmt.Errorf("invalid bulk length")
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(rd, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:n]))
	}
	return args, nil
}
