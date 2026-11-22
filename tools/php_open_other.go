//go:build !unix

package tools

import "os"

// phpOpenFlags: no FIFO to wait for here (Windows reads go through the
// Windows source).
const phpOpenFlags = os.O_RDONLY
