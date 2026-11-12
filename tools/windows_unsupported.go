package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
)

// Tools that still read Linux sources (log files, iptables/nftables);
// ssh_logins, processes and accounts_audit have Windows versions. On Windows they must say so: an empty result
// would tell the model the host is clean. Each is replaced by a real
// Windows implementation before v0.3.0. Block and unblock are control
// tools: the Windows MVP makes no changes to the host.
var windowsUnsupported = map[string]bool{
	"log_search": true,
	"block_ip":   true, "unblock_ip": true,
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
