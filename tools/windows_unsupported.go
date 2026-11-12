package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
)

// Tools that only work on Linux: block_ip and unblock_ip drive
// iptables/nftables, and the Windows MVP makes no changes to the host
// (they stay refused through v0.3.0). On Windows they must say so rather
// than return nothing. ssh_logins, processes, accounts_audit and
// log_search have Windows versions.
var windowsUnsupported = map[string]bool{
	"block_ip": true, "unblock_ip": true,
}

// unsupportedHere is true on Windows; tests flip it.
var unsupportedHere = runtime.GOOS == "windows"

// errUnsupported is what such a tool returns on Windows.
func errUnsupported(name string) error {
	return fmt.Errorf("%s is not supported on Windows yet; see site_profile (Windows facts and checks: accounts, processes, logon failures, firewall, autostart entries)", name)
}

// guardWindows replaces the Run (and Preview) of the tools above with an
// error on Windows.
func guardWindows(ts []Tool) []Tool {
	if !unsupportedHere {
		return ts
	}
	for i := range ts {
		if !windowsUnsupported[ts[i].Name] {
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
