//go:build !windows

package hostenv

import "os"

func elevated() bool { return os.Geteuid() == 0 }
