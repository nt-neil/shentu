//go:build !unix

package tools

import "os"

// phpOpenFlags: no FIFO to wait for here. Windows reads are local
// absolute paths only, their links resolved first (phpWinLocal).
const phpOpenFlags = os.O_RDONLY
