package orchestrator

import (
	"bytes"
	"encoding/binary"
	"sort"
	"strings"
)

// Cowrie fs.pickle node type constants matching cowrie/shell/fs.py.
const (
	cowrieTypeLink = 0
	cowrieTypeDir  = 1
	cowrieTypeFile = 2
)

// FSNode represents one inode entry inside Cowrie's fs.pickle filesystem tree.
type FSNode struct {
	Name     string
	Type     int
	UID      int
	GID      int
	Size     int
	Mode     int
	CTime    int64
	Target   string
	Children []*FSNode
}

// DefaultCowrieTree constructs a baseline Linux root filesystem tree merged with extra seeded files.
func DefaultCowrieTree(nowUnix int64, seededFiles map[string]int) *FSNode {
	root := &FSNode{
		Name:  "/",
		Type:  cowrieTypeDir,
		UID:   0,
		GID:   0,
		Mode:  0o040755,
		CTime: nowUnix - 86400*90,
	}
	basePaths := map[string]int{
		"/etc/passwd":             942,
		"/etc/group":              512,
		"/etc/issue":              28,
		"/etc/hosts":              158,
		"/var/log/auth.log":       1024,
		"/usr/bin/curl":           215040,
		"/usr/bin/wget":           481200,
		"/bin/bash":               1234376,
		"/bin/sh":                 129816,
		"/tmp/.keep":              0,
		"/root/.bashrc":           3106,
		"/home/deploy/.bashrc":    3106,
	}
	for p, sz := range basePaths {
		if _, exists := seededFiles[p]; !exists {
			ensureFileNode(root, p, sz, 0o100644, 0, 0, nowUnix-86400*30)
		}
	}
	for p, sz := range seededFiles {
		uid, gid := 0, 0
		mode := 0o100600
		if strings.HasPrefix(p, "/home/deploy/") {
			uid, gid = 1000, 1000
		}
		if strings.HasPrefix(p, "/var/www/") {
			uid, gid = 33, 33
			mode = 0o100640
		}
		ensureFileNode(root, p, sz, mode, uid, gid, nowUnix-3600)
	}
	sortTree(root)
	return root
}

func ensureFileNode(root *FSNode, fullPath string, size, mode, uid, gid int, ctime int64) {
	parts := strings.Split(strings.Trim(fullPath, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return
	}
	cur := root
	for i := 0; i < len(parts)-1; i++ {
		dirName := parts[i]
		dirUID, dirGID := 0, 0
		if i >= 1 && parts[0] == "home" && parts[1] == "deploy" {
			dirUID, dirGID = 1000, 1000
		}
		if i >= 1 && parts[0] == "var" && parts[1] == "www" {
			dirUID, dirGID = 33, 33
		}
		var next *FSNode
		for _, ch := range cur.Children {
			if ch.Name == dirName && ch.Type == cowrieTypeDir {
				next = ch
				break
			}
		}
		if next == nil {
			next = &FSNode{
				Name:  dirName,
				Type:  cowrieTypeDir,
				UID:   dirUID,
				GID:   dirGID,
				Size:  4096,
				Mode:  0o040755,
				CTime: ctime,
			}
			cur.Children = append(cur.Children, next)
		}
		cur = next
	}
	fileName := parts[len(parts)-1]
	for _, ch := range cur.Children {
		if ch.Name == fileName {
			ch.Type = cowrieTypeFile
			ch.Size = size
			ch.Mode = mode
			ch.UID = uid
			ch.GID = gid
			ch.CTime = ctime
			return
		}
	}
	cur.Children = append(cur.Children, &FSNode{
		Name:  fileName,
		Type:  cowrieTypeFile,
		UID:   uid,
		GID:   gid,
		Size:  size,
		Mode:  mode,
		CTime: ctime,
	})
}

func sortTree(n *FSNode) {
	sort.Slice(n.Children, func(i, j int) bool {
		return n.Children[i].Name < n.Children[j].Name
	})
	for _, ch := range n.Children {
		sortTree(ch)
	}
}

// MarshalCowriePickle serializes root into a Python Pickle protocol v2 binary matching Cowrie fs.pickle.
func MarshalCowriePickle(root *FSNode) []byte {
	var buf bytes.Buffer
	// PROTO 2
	buf.WriteByte(0x80)
	buf.WriteByte(0x02)
	writePickleNode(&buf, root)
	// STOP
	buf.WriteByte('.')
	return buf.Bytes()
}

func writePickleNode(buf *bytes.Buffer, n *FSNode) {
	// Cowrie fs.pickle node layout: [A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE]
	buf.WriteByte(']') // EMPTY_LIST
	buf.WriteByte('(') // MARK

	writePickleStr(buf, n.Name)
	writePickleInt(buf, int64(n.Type))
	writePickleInt(buf, int64(n.UID))
	writePickleInt(buf, int64(n.GID))
	writePickleInt(buf, int64(n.Size))
	writePickleInt(buf, int64(n.Mode))
	writePickleInt(buf, n.CTime)

	if n.Type == cowrieTypeDir {
		buf.WriteByte(']')
		if len(n.Children) > 0 {
			buf.WriteByte('(')
			for _, ch := range n.Children {
				writePickleNode(buf, ch)
			}
			buf.WriteByte('e') // APPENDS
		}
	} else {
		buf.WriteByte('N') // NONE (content served from honeyfs overlay)
	}

	if n.Target != "" {
		writePickleStr(buf, n.Target)
	} else {
		buf.WriteByte('N')
	}
	buf.WriteByte('N') // A_REALFILE = None

	buf.WriteByte('e') // APPENDS
}

func writePickleStr(buf *bytes.Buffer, s string) {
	b := []byte(s)
	// BINUNICODE 'X' + 4-byte little-endian length
	buf.WriteByte('X')
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(b)))
	buf.Write(lenBuf[:])
	buf.Write(b)
}

func writePickleInt(buf *bytes.Buffer, v int64) {
	switch {
	case v >= 0 && v <= 255:
		buf.WriteByte('K') // BININT1
		buf.WriteByte(byte(v))
	case v >= 0 && v <= 65535:
		buf.WriteByte('M') // BININT2
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], uint16(v))
		buf.Write(b[:])
	default:
		buf.WriteByte('J') // BININT (signed 32-bit LE)
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(int32(v)))
		buf.Write(b[:])
	}
}
