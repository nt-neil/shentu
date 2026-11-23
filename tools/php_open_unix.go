//go:build unix

package tools

import (
	"os"
	"syscall"
)

// phpOpenFlags opens without waiting: a FIFO opened for reading would block
// until a writer comes; with O_NONBLOCK the open returns and fstat says it
// is not a regular file.
const phpOpenFlags = os.O_RDONLY | syscall.O_NONBLOCK
