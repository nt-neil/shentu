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
