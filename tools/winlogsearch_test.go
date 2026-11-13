package tools

import (
	"errors"
	"strings"
	"testing"
)

func TestWinLogSearch(t *testing.T) {
	old := winEventText
	t.Cleanup(func() { winEventText = old })
	lines := []string{
		"2026-11-12T15:03:00Z System 7045: ServiceName=evil ImagePath=C:\\Users\\Public\\x.exe",
		"2026-11-12T15:02:00Z System 7036: param1=Windows Update param2=running",
		"2026-11-12T15:01:00Z System 7045: ServiceName=other ImagePath=C:\\Windows\\other.exe",
	}
	var gotChannel string
	winEventText = func(channel, xpath string, max int, f func(string) bool) error {
		gotChannel = channel
		for _, l := range lines {
			if !f(l) {
				break
			}
		}
		return nil
	}
	out, err := winLogSearch("system", `7045:`, 1)
	if err != nil {
		t.Fatal(err)
	}
	m := out["matches"].([]string)
	if gotChannel != "System" || len(m) != 1 || !strings.Contains(m[0], "ServiceName=evil") {
		t.Errorf("newest match first, limit kept, channel normalised: %q %v", gotChannel, m)
	}
	if _, err := winLogSearch(`C:\Windows\System32\config\SAM`, "x", 10); err == nil {
		t.Error("only the listed event logs may be read")
	}
	if _, err := winLogSearch("Security", "(", 10); err == nil {
		t.Error("a bad pattern is an error")
	}
	winEventText = func(string, string, int, func(string) bool) error { return errors.New("access denied") }
	if out, err := winLogSearch("Security", "4625", 10); err == nil || out != nil {
		t.Error("an unreadable log must be an error, never an empty result")
	}
}
