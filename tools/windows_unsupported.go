package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
)

// windowsSupported are the tools that work on Windows. Default deny: a
// tool not listed (a new Linux-only one, or block_ip and unblock_ip, which
// drive iptables/nftables while the Windows MVP changes nothing) refuses
// on Windows rather than returning an empty, clean-looking result.
var windowsSupported = map[string]bool{
	"ssh_logins": true, "listening_ports": true, "processes": true, "accounts_audit": true,
	"package_vulns": true, "app_vulns": true, "app_code_audit": true, "site_profile": true,
	"file_changes": true, "cert_expiry": true, "log_search": true, "notify": true,
}

// darwinSupported are the tools that read macOS itself; the others still
// read Linux's sources there (/proc, Linux log paths) and would come back
// empty, which must not pass for clean. The platform's own readers are
// for later.
var darwinSupported = map[string]bool{
	"package_vulns": true, "app_vulns": true, "app_code_audit": true, "site_profile": true, "notify": true,
	"listening_ports": true, "processes": true, // M0: hostenv's darwin collector (netstat/lsof, ps)
	// not cert_expiry yet: its certbot paths are Linux's, not Homebrew's
}

// SupportedOn says whether tool name gives a real result on goos.
func SupportedOn(name, goos string) bool {
	switch goos {
	case "linux":
		return true
	case "windows":
		return windowsSupported[name]
	case "darwin":
		return darwinSupported[name]
	}
	return false
}

// unsupportedHere is true on Windows; tests flip it.
var unsupportedHere = runtime.GOOS == "windows"

// errUnsupported is what such a tool returns on Windows.
func errUnsupported(name string) error {
	return fmt.Errorf("%s is not supported on Windows yet; see site_profile (Windows facts and checks: accounts, processes, logon failures, firewall, autostart entries)", name)
}

// guardWindows replaces the Run (and Preview) of every tool not in
// windowsSupported with an error on Windows.
func guardWindows(ts []Tool) []Tool {
	if !unsupportedHere {
		return ts
	}
	for i := range ts {
		if windowsSupported[ts[i].Name] {
			continue
		}
		name := ts[i].Name
		ts[i].Run = func(context.Context, *Env, json.RawMessage) (any, error) { return nil, errUnsupported(name) }
		if ts[i].Preview != nil {
			ts[i].Preview = func(json.RawMessage) (string, error) { return "", errUnsupported(name) }
		}
	}
	return ts
}
