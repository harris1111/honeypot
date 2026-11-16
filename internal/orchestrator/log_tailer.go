package orchestrator

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
)

type tailBookmark struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

// LogTailer tails newline-delimited files with persistent inode/offset bookmarks across restarts and log rotations.
type LogTailer struct {
	path         string
	bookmarkPath string
	bookmark     tailBookmark
}

// OpenLogTailer creates a LogTailer restoring any saved offset bookmark.
func OpenLogTailer(logPath, bookmarkPath string) *LogTailer {
	t := &LogTailer{path: logPath, bookmarkPath: bookmarkPath}
	if b, err := os.ReadFile(bookmarkPath); err == nil {
		_ = json.Unmarshal(b, &t.bookmark)
	}
	return t
}

// ReadNewLines reads complete lines appended since the last bookmark and updates bookmark atomically.
func (t *LogTailer) ReadNewLines() ([]string, error) {
	f, err := os.Open(t.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	var inode uint64
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		inode = st.Ino
	}

	// Reset offset if rotated or truncated
	if (t.bookmark.Inode != 0 && inode != t.bookmark.Inode) || info.Size() < t.bookmark.Offset {
		t.bookmark.Offset = 0
	}
	t.bookmark.Inode = inode

	if _, err := f.Seek(t.bookmark.Offset, 0); err != nil {
		return nil, err
	}

	var lines []string
	reader := bufio.NewReader(f)
	var consumed int64
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			consumed += int64(len(line))
			lines = append(lines, line[:len(line)-1])
		}
		if err != nil {
			break
		}
	}
	if consumed > 0 {
		t.bookmark.Offset += consumed
		t.saveBookmark()
	}
	return lines, nil
}

func (t *LogTailer) saveBookmark() {
	if t.bookmarkPath == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(t.bookmarkPath), 0o700)
	b, _ := json.Marshal(t.bookmark)
	_ = os.WriteFile(t.bookmarkPath, b, 0o600)
}
