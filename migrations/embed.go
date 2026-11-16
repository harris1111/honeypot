package migrations

import "embed"

// FS embeds all SQL schema migrations for goose.SetBaseFS.
//
//go:embed *.sql
var FS embed.FS
