//go:build !linux

package tools

import "io/fs"

// Docker's overlay2 store is Linux's: elsewhere there are no overlayfs
// marks to read.
func overlayWhiteoutFile(fs.FileInfo) bool { return false }

func overlayOpaqueDir(string) bool { return false }
