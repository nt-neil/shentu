//go:build !linux && !darwin && !windows

package hostenv

import (
	"io/fs"
	"time"
)

// statExtra elsewhere: not read (nil), not said not to apply.
func statExtra(fs.FileInfo) (*time.Time, *uint64, []string) { return nil, nil, nil }
