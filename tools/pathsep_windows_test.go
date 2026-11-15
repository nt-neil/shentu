//go:build windows

package tools

import "testing"

func TestInsideAnyWindows(t *testing.T) {
	roots := []string{`C:\inetpub\wwwroot`}
	for p, want := range map[string]bool{
		`C:\inetpub\wwwroot\uploads\a.aspx`: true, `c:\INETPUB\WWWROOT\x`: true,
		`C:\inetpub\wwwroot-old\x`: false, `D:\inetpub\wwwroot\x`: false,
	} {
		if got := insideAny(p, roots); got != want {
			t.Errorf("insideAny(%q) = %v, want %v", p, got, want)
		}
	}
	if !served(`C:\sites\shop\public\index.php`, nil) {
		t.Error("served must split on \\ too")
	}
}
