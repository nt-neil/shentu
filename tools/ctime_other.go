//go:build !linux

package tools

import (
	"io/fs"
	"time"
)

// Shentu targets Linux; this lets the code build elsewhere for development.
func ctimeUID(info fs.FileInfo) (time.Time, uint32, bool) { return time.Time{}, 0, false }
