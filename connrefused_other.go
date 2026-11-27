//go:build !windows

package main

import (
	"errors"
	"syscall"
)

// connRefused: the far end refused the connection.
func connRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }
