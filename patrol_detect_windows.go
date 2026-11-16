//go:build windows

package main

import "os"

// ownDir: on Windows the state directory's ACL is set by ensureStateDir;
// there is no uid to compare.
func ownDir(os.FileInfo) bool { return true }
