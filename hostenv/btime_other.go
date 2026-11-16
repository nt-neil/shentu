//go:build !linux && !darwin && !windows

package hostenv

import (
	"os"
	"time"
)

// pathBorn and fileBorn are not known here: zero.
func pathBorn(string) time.Time { return time.Time{} }

func fileBorn(*os.File, os.FileInfo) time.Time { return time.Time{} }
