package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var rawDist embed.FS

// DistFS returns the compiled Vite + React Admin Console subtree rooted at index.html.
func DistFS() fs.FS {
	sub, err := fs.Sub(rawDist, "dist")
	if err != nil {
		return nil
	}
	return sub
}
