package main

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// connRefused: the far end refused the connection. On Windows a dial gives
// WSAECONNREFUSED (10061), not syscall.ECONNREFUSED (S-275-1).
func connRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, windows.WSAECONNREFUSED)
}
