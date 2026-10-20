// Package web embeds the browser UI.
package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var files embed.FS

// Static is the UI's file tree, rooted at static/.
func Static() fs.FS {
	sub, err := fs.Sub(files, "static")
	if err != nil {
		panic(err)
	}
	return sub
}
