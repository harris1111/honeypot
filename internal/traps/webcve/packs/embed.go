package packs

import "embed"

// FS embeds all 13 declarative YAML Web CVE exploit packs.
//
//go:embed *.yaml
var FS embed.FS
