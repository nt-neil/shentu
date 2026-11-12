//go:build windows

package hostenv

import "os"

// fileUID has no meaning on Windows: owners are SIDs (Phase 2).
func fileUID(os.FileInfo) int { return -1 }
