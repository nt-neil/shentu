package hostenv

import (
	"path/filepath"
	"runtime"
	"testing"
)

// winPaths gives Windows' answers on any OS; on Windows they are held to
// filepath's own.
func TestWinPathsAsFilepath(t *testing.T) {
	type c struct{ in, want string }
	check := func(name string, f, native func(string) string, cases []c) {
		for _, x := range cases {
			if got := f(x.in); got != x.want {
				t.Errorf("%s(%q) = %q, want %q", name, x.in, got, x.want)
			}
			if runtime.GOOS == "windows" {
				if n := native(x.in); n != x.want {
					t.Errorf("filepath.%s(%q) = %q, the table says %q", name, x.in, n, x.want)
				}
			}
		}
	}
	check("Clean", winClean, filepath.Clean, []c{
		{`C:\a\..\b`, `C:\b`}, {`C:/x/./y/`, `C:\x\y`}, {`C:`, `C:.`}, {`C:\`, `C:\`},
		{`\\srv\sh\x\..`, `\\srv\sh\`}, {`a\..\..\b`, `..\b`}, {``, `.`}, {`\a\\b`, `\a\b`},
		{`C:\..\x`, `C:\x`},
	})
	check("Dir", winDir, filepath.Dir, []c{
		{`C:\a\b.txt`, `C:\a`}, {`C:\a`, `C:\`}, {`\\srv\sh\f`, `\\srv\sh\`}, {`x`, `.`}, {`C:x`, `C:.`},
	})
	check("Base", winBase, filepath.Base, []c{
		{`C:\a\b.txt`, `b.txt`}, {`C:\`, `\`}, {`a\b\`, `b`}, {``, `.`}, {`C:x`, `x`},
	})
	check("Ext", winExt, filepath.Ext, []c{{`a\b.tar.gz`, `.gz`}, {`a.b\c`, ``}, {`C:\x.ASP`, `.ASP`}})
	check("FromSlash", winFromSlash, filepath.FromSlash, []c{{`C:/inetpub/wwwroot`, `C:\inetpub\wwwroot`}})
	for _, x := range []struct {
		elem []string
		want string
	}{
		{[]string{`C:`, `x`}, `C:x`}, {[]string{`C:\a`, `b`}, `C:\a\b`}, {[]string{`a`, ``, `b`}, `a\b`},
		{[]string{`C:\inetpub`, `wwwroot`, `..`, `logs`}, `C:\inetpub\logs`},
	} {
		if got := winJoin(x.elem...); got != x.want {
			t.Errorf("Join(%q) = %q, want %q", x.elem, got, x.want)
		}
		if runtime.GOOS == "windows" {
			if n := filepath.Join(x.elem...); n != x.want {
				t.Errorf("filepath.Join(%q) = %q, the table says %q", x.elem, n, x.want)
			}
		}
	}
	for in, want := range map[string]bool{`C:\x`: true, `C:x`: false, `\x`: false, `\\srv\sh\x`: true, `x`: false} {
		if got := winIsAbs(in); got != want {
			t.Errorf("IsAbs(%q) = %v", in, got)
		}
		if runtime.GOOS == "windows" && filepath.IsAbs(in) != want {
			t.Errorf("filepath.IsAbs(%q) = %v, the table says %v", in, filepath.IsAbs(in), want)
		}
	}
	if ok, _ := winMatch(`C:\a\*.php`, `C:\a\x.php`); !ok {
		t.Error("Match")
	}
	if PathFor(fakeWinInfo{}).Sep != `\` {
		t.Error("a Windows host read: not Windows' paths")
	}
}

// fakeWinInfo is a Source that says it reads Windows.
type fakeWinInfo struct{ fakeMac }

func (fakeWinInfo) Info() SourceInfo { return SourceInfo{GOOS: "windows", GOARCH: "amd64"} }
