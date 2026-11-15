package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestLinuxOnlyToolsErrorOnWindows(t *testing.T) {
	old := unsupportedHere
	unsupportedHere = true
	t.Cleanup(func() { unsupportedHere = old })
	names := map[string]bool{}
	refused := 0
	for _, tl := range All() {
		names[tl.Name] = true
		if windowsSupported[tl.Name] {
			continue
		}
		refused++
		out, err := tl.Run(context.Background(), &Env{}, nil)
		if err == nil || out != nil || !strings.Contains(err.Error(), "not supported on Windows") {
			t.Errorf("%s on Windows: %v, %v; want an error, never an empty result", tl.Name, out, err)
		}
		if tl.Preview != nil {
			if _, err := tl.Preview(nil); err == nil {
				t.Errorf("%s preview on Windows must refuse too", tl.Name)
			}
		}
	}
	for n := range windowsSupported {
		if !names[n] {
			t.Errorf("%s is listed as supported on Windows but is no tool", n)
		}
	}
	if !names["block_ip"] || windowsSupported["block_ip"] || windowsSupported["unblock_ip"] || refused < 2 {
		t.Error("block_ip and unblock_ip must be refused on Windows")
	}
}

// Default deny: a tool added without a Windows version is refused there.
func TestNewToolDeniedOnWindows(t *testing.T) {
	old := unsupportedHere
	unsupportedHere = true
	t.Cleanup(func() { unsupportedHere = old })
	ts := guardWindows([]Tool{{Name: "brand_new_linux_tool", Run: func(context.Context, *Env, json.RawMessage) (any, error) { return "linux data", nil }}})
	if _, err := ts[0].Run(context.Background(), &Env{}, nil); err == nil {
		t.Error("a tool not on the Windows list must refuse there")
	}
}
