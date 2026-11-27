package main

import (
	"net"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// S-275-1: on Windows a refused dial is WSAECONNREFUSED: said as refused.
func TestOpaqueDoErrorWSARefused(t *testing.T) {
	err := &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connectex", Err: windows.WSAECONNREFUSED}}
	if got := opaqueDoError(t.Context(), err).Error(); !strings.HasSuffix(got, "connection refused") {
		t.Errorf("%q", got)
	}
}
