//go:build windows

package main

import "os"

// ownDir: on Windows the state directory's ACL is set by ensureStateDir;
// there is no uid to compare.
func ownDir(os.FileInfo) bool { return true }

// detectStateDir is ensureStateDir on Windows (its ACL is set there).
func detectStateDir(dir string, _ bool) error { return ensureStateDir(dir) }
