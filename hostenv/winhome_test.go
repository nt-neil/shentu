package hostenv

import (
	"strings"
	"testing"
)

// Round 3 re-review: a path below a Windows profile is masked to the end
// of its field, as /Users and /home are (f116214); the Startup folder and
// the temp folder's name stay for the collector.
func TestMaskWinHome(t *testing.T) {
	leak := []string{"Acme", "Inc (2026)", "q3:plan", "secret project", "x.exe"}
	for _, in := range []string{
		`C:\Users\alice\Clients\Acme, Inc (2026)\q3:plan`,
		`"C:\\Users\\alice\\Clients\\Acme, Inc (2026)\\q3:plan"`,
		`run C:\Users\Public\Documents\secret project\x.exe -flag`,
	} {
		out := maskWinHome(in)
		for _, l := range leak {
			if strings.Contains(out, l) {
				t.Errorf("%s -> %s leaks %q", in, out, l)
			}
		}
		if !strings.Contains(out, "redacted-") {
			t.Errorf("%s -> %s", in, out)
		}
	}
	// The field ends at a quote: what follows is another field.
	if out := maskWinHome(`"C:\\Users\\bob\\a b","next"`); !strings.HasSuffix(out, `","next"`) || strings.Contains(out, "a b") {
		t.Errorf("field end: %s", out)
	}
	// Same path, same placeholder; plain and JSON alike.
	a, b := maskWinHome(`C:\Users\bob\Docs\plan.txt`), maskWinHome(`"C:\\Users\\bob\\Docs\\plan.txt"`)
	if strings.TrimPrefix(a, `C:\Users\bob\`) != strings.Trim(strings.TrimPrefix(b, `"C:\\Users\\bob\\`), `"`) {
		t.Errorf("not consistent: %s / %s", a, b)
	}
	// Kept: Startup whole, the temp folder by name.
	st := `C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\My App.lnk`
	if out := maskWinHome(st); out != st {
		t.Errorf("Startup: %s", out)
	}
	if out := maskWinHome(`C:\Users\bob\AppData\Local\Temp\dropper.exe`); !strings.HasPrefix(out, `C:\Users\bob\AppData\Local\Temp\redacted-`) || !WinInTempDir(out) {
		t.Errorf("Temp: %s", out)
	}
	if out := maskWinHome(`C:\Users\bob\AppData\Local\Temp`); out != `C:\Users\bob\AppData\Local\Temp` {
		t.Errorf("Temp folder itself: %s", out)
	}
	if out := maskWinHome(`C:\Users\bob`); out != `C:\Users\bob` {
		t.Errorf("a profile folder alone: %s", out)
	}
}
