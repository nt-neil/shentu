//go:build windows

package hostenv

import "golang.org/x/sys/windows"

// elevated reports whether this process runs with an elevated token
// (TokenElevation). A filtered Administrator token counts as not elevated,
// so permission-dependent facts come out partial or unknown, never clean.
func elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }
