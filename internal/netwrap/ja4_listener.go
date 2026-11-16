package netwrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/netutil"
)

const (
	maxClientHelloPeek = 16 * 1024
	ja4ReadTimeout     = 3 * time.Second
)

type ja4CtxKey struct{}

// WithJA4ConnContext attaches the underlying *JA4Conn (if present, even wrapped inside *tls.Conn) to ctx.
func WithJA4ConnContext(ctx context.Context, c net.Conn) context.Context {
	if jc := unwrapJA4Conn(c); jc != nil {
		return context.WithValue(ctx, ja4CtxKey{}, jc)
	}
	return ctx
}

// JA4FromContext returns the computed JA4 fingerprint for the connection serving r, or "" if plaintext HTTP.
func JA4FromContext(ctx context.Context) string {
	jc, ok := ctx.Value(ja4CtxKey{}).(*JA4Conn)
	if !ok || jc == nil {
		return ""
	}
	return jc.JA4()
}

// SNIFromContext returns the parsed TLS ClientHello SNI if available.
func SNIFromContext(ctx context.Context) string {
	jc, ok := ctx.Value(ja4CtxKey{}).(*JA4Conn)
	if !ok || jc == nil {
		return ""
	}
	return jc.SNI()
}

func unwrapJA4Conn(c net.Conn) *JA4Conn {
	for c != nil {
		if jc, ok := c.(*JA4Conn); ok {
			return jc
		}
		if nc, ok := c.(interface{ NetConn() net.Conn }); ok {
			c = nc.NetConn()
			continue
		}
		break
	}
	return nil
}

// JA4Listener wraps an inner net.Listener with concurrency limits and per-conn ClientHello JA4 inspection.
// Accept() returns immediately without blocking on network reads.
type JA4Listener struct {
	inner net.Listener
}

// NewJA4Listener wraps ln with netutil.LimitListener (default 2048) and non-blocking JA4Conn wrapping.
func NewJA4Listener(ln net.Listener, maxConns int) *JA4Listener {
	if maxConns <= 0 {
		maxConns = 2048
	}
	return &JA4Listener{inner: netutil.LimitListener(ln, maxConns)}
}

func (l *JA4Listener) Accept() (net.Conn, error) {
	c, err := l.inner.Accept()
	if err != nil {
		return nil, err
	}
	return &JA4Conn{Conn: c}, nil
}

func (l *JA4Listener) Close() error   { return l.inner.Close() }
func (l *JA4Listener) Addr() net.Addr { return l.inner.Addr() }

// JA4Conn inspects up to 16 KiB of initial TLS ClientHello records on first Read inside the connection goroutine,
// computes the FoxIO JA4 fingerprint + SNI, and replays the exact buffered bytes without altering the TLS stream.
type JA4Conn struct {
	net.Conn

	mu        sync.Mutex
	inspected bool
	replay    []byte
	offset    int
	ja4       string
	sni       string
}

// JA4 returns the computed JA4 fingerprint string (empty for non-TLS traffic).
func (c *JA4Conn) JA4() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ja4
}

// SNI returns the parsed TLS Server Name Indication (empty for raw IP connections).
func (c *JA4Conn) SNI() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sni
}

func (c *JA4Conn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if !c.inspected {
		c.inspected = true
		c.peekClientHelloLocked()
	}
	if c.offset < len(c.replay) {
		n := copy(b, c.replay[c.offset:])
		c.offset += n
		if c.offset >= len(c.replay) {
			c.replay = nil
		}
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	return c.Conn.Read(b)
}

func (c *JA4Conn) peekClientHelloLocked() {
	_ = c.Conn.SetReadDeadline(time.Now().Add(ja4ReadTimeout))
	defer func() { _ = c.Conn.SetReadDeadline(time.Time{}) }()

	var buf bytes.Buffer
	tmp := make([]byte, 4096)

	for buf.Len() < maxClientHelloPeek {
		n, err := c.Conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		data := buf.Bytes()
		if len(data) == 0 {
			break
		}
		// Non-TLS (e.g., plaintext HTTP on port 80) -> exit immediately on first read without waiting
		if data[0] != 0x16 {
			break
		}
		if len(data) >= 5 {
			need, ok := expectedClientHelloBytes(data)
			if !ok || len(data) >= need {
				break
			}
		}
		if err != nil {
			if err != io.EOF {
				// Partial peek still replayable cleanly
			}
			break
		}
	}

	raw := buf.Bytes()
	if len(raw) > 0 {
		c.replay = append([]byte(nil), raw...)
		if fp, sni, ok := ComputeJA4FromTLSRecords(raw); ok {
			c.ja4 = fp
			c.sni = sni
		}
	}
}

func expectedClientHelloBytes(data []byte) (int, bool) {
	// Accumulate TLS handshake payload across 1 or more 0x16 records until ClientHello handshake length is reached.
	pos := 0
	var handshakeTotal int
	var haveHandshakeLen bool
	var assembled int

	for pos+5 <= len(data) {
		if data[pos] != 0x16 {
			return len(data), false
		}
		recLen := int(binary.BigEndian.Uint16(data[pos+3 : pos+5]))
		if recLen <= 0 || recLen > maxClientHelloPeek {
			return len(data), false
		}
		recEnd := pos + 5 + recLen
		if !haveHandshakeLen && pos+9 <= len(data) {
			if data[pos+5] != 0x01 { // Handshake type != ClientHello
				return len(data), false
			}
			hsLen := int(data[pos+6])<<16 | int(data[pos+7])<<8 | int(data[pos+8])
			if hsLen <= 0 || hsLen > maxClientHelloPeek {
				return len(data), false
			}
			handshakeTotal = 4 + hsLen
			haveHandshakeLen = true
		}
		assembled += recLen
		if haveHandshakeLen && assembled >= handshakeTotal {
			return recEnd, true
		}
		pos = recEnd
	}
	return maxClientHelloPeek, true
}

// ComputeJA4FromTLSRecords extracts TLS handshake records (handling multi-record fragmented ClientHello) and computes JA4.
func ComputeJA4FromTLSRecords(raw []byte) (ja4 string, sni string, ok bool) {
	if len(raw) < 9 || raw[0] != 0x16 {
		return "", "", false
	}
	var hsPayload []byte
	pos := 0
	for pos+5 <= len(raw) && raw[pos] == 0x16 {
		recLen := int(binary.BigEndian.Uint16(raw[pos+3 : pos+5]))
		if pos+5+recLen > len(raw) {
			hsPayload = append(hsPayload, raw[pos+5:]...)
			break
		}
		hsPayload = append(hsPayload, raw[pos+5:pos+5+recLen]...)
		pos += 5 + recLen
		if len(hsPayload) >= 4 {
			hsLen := int(hsPayload[1])<<16 | int(hsPayload[2])<<8 | int(hsPayload[3])
			if len(hsPayload) >= 4+hsLen {
				hsPayload = hsPayload[:4+hsLen]
				break
			}
		}
	}
	if len(hsPayload) < 42 || hsPayload[0] != 0x01 {
		return "", "", false
	}
	return parseClientHelloJA4(hsPayload[4:])
}

func parseClientHelloJA4(body []byte) (string, string, bool) {
	if len(body) < 35 {
		return "", "", false
	}
	legacyVer := binary.BigEndian.Uint16(body[0:2])
	idx := 34 // 2 bytes version + 32 bytes random

	if idx >= len(body) {
		return "", "", false
	}
	sessLen := int(body[idx])
	idx += 1 + sessLen
	if idx+2 > len(body) {
		return "", "", false
	}

	csLen := int(binary.BigEndian.Uint16(body[idx : idx+2]))
	idx += 2
	if csLen%2 != 0 || idx+csLen > len(body) {
		return "", "", false
	}
	var ciphers []uint16
	for j := 0; j < csLen; j += 2 {
		cs := binary.BigEndian.Uint16(body[idx+j : idx+j+2])
		if !isGREASE(cs) {
			ciphers = append(ciphers, cs)
		}
	}
	idx += csLen
	if idx >= len(body) {
		return "", "", false
	}

	compLen := int(body[idx])
	idx += 1 + compLen

	var exts []uint16
	var sigAlgs []uint16
	var sniHost string
	alpnCode := "00"
	bestVer := legacyVer

	if idx+2 <= len(body) {
		extTotalLen := int(binary.BigEndian.Uint16(body[idx : idx+2]))
		idx += 2
		extEnd := idx + extTotalLen
		if extEnd > len(body) {
			extEnd = len(body)
		}
		for idx+4 <= extEnd {
			extType := binary.BigEndian.Uint16(body[idx : idx+2])
			extLen := int(binary.BigEndian.Uint16(body[idx+2 : idx+4]))
			idx += 4
			if idx+extLen > extEnd {
				break
			}
			extData := body[idx : idx+extLen]
			idx += extLen

			if isGREASE(extType) {
				continue
			}
			// JA4 extension list excludes SNI (0x0000) and ALPN (0x0010)
			if extType != 0x0000 && extType != 0x0010 {
				exts = append(exts, extType)
			}

			switch extType {
			case 0x0000: // server_name
				if s := parseSNI(extData); s != "" {
					sniHost = s
				}
			case 0x0010: // ALPN
				if a := parseALPNFirst(extData); a != "" {
					alpnCode = a
				}
			case 0x000d: // signature_algorithms (unsorted in hash per JA4 spec)
				if len(extData) >= 2 {
					saLen := int(binary.BigEndian.Uint16(extData[:2]))
					for k := 2; k+2 <= len(extData) && k < 2+saLen; k += 2 {
						sigAlgs = append(sigAlgs, binary.BigEndian.Uint16(extData[k:k+2]))
					}
				}
			case 0x002b: // supported_versions
				if len(extData) >= 1 {
					vLen := int(extData[0])
					var maxV uint16
					for k := 1; k+2 <= len(extData) && k < 1+vLen; k += 2 {
						v := binary.BigEndian.Uint16(extData[k : k+2])
						if !isGREASE(v) && v > maxV {
							maxV = v
						}
					}
					if maxV != 0 {
						bestVer = maxV
					}
				}
			}
		}
	}

	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	sort.Slice(exts, func(i, j int) bool { return exts[i] < exts[j] })

	sniChar := "i"
	if sniHost != "" {
		sniChar = "d"
	}
	cCount := clampTwoDigits(len(ciphers))
	eCount := clampTwoDigits(len(exts))
	verStr := tlsVersionCode(bestVer)

	cipherStr := joinHexUint16(ciphers)
	cipherHash := sha12(cipherStr)

	extStr := joinHexUint16(exts)
	if len(sigAlgs) > 0 {
		extStr += "_" + joinHexUint16(sigAlgs)
	}
	extHash := sha12(extStr)

	fp := fmt.Sprintf("t%s%s%02d%02d%s_%s_%s", verStr, sniChar, cCount, eCount, alpnCode, cipherHash, extHash)
	return fp, sniHost, true
}

func isGREASE(v uint16) bool {
	return (v & 0x0f0f) == 0x0a0a
}

func tlsVersionCode(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	default:
		return "00"
	}
}

func parseSNI(extData []byte) string {
	if len(extData) < 5 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(extData[:2]))
	if listLen+2 > len(extData) {
		return ""
	}
	pos := 2
	for pos+3 <= 2+listLen {
		nameType := extData[pos]
		nameLen := int(binary.BigEndian.Uint16(extData[pos+1 : pos+3]))
		pos += 3
		if pos+nameLen > len(extData) {
			break
		}
		if nameType == 0x00 {
			return string(extData[pos : pos+nameLen])
		}
		pos += nameLen
	}
	return ""
}

func parseALPNFirst(extData []byte) string {
	if len(extData) < 4 {
		return ""
	}
	pLen := int(extData[2])
	if pLen <= 0 || 3+pLen > len(extData) {
		return ""
	}
	proto := string(extData[3 : 3+pLen])
	if len(proto) >= 2 {
		return proto[:1] + proto[len(proto)-1:]
	}
	return proto + "0"
}

func clampTwoDigits(n int) int {
	if n > 99 {
		return 99
	}
	return n
}

func joinHexUint16(vals []uint16) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func sha12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
