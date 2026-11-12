package tools

// Phase 1c zero-diff harness: the pre-migration implementations, kept here
// verbatim (test-only), run against the same recorded inputs as the new
// hostenv path. A category is migrated when both agree on every fixture.

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// fixtures replays every Linux fixture of hostenv/testdata.
func fixtures(t *testing.T) map[string]*hostenv.Replay {
	dirs, _ := filepath.Glob(filepath.Join("..", "hostenv", "testdata", "linux", "*", "manifest.json"))
	if len(dirs) == 0 {
		t.Skip("no hostenv fixtures")
	}
	out := map[string]*hostenv.Replay{}
	for _, m := range dirs {
		rp, err := hostenv.LoadReplay(filepath.Dir(m))
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(filepath.Dir(m))] = rp
	}
	return out
}

// withHost points the tools at src for one test.
func withHost(t *testing.T, src hostenv.Source) {
	old := hostSource
	hostSource = func() hostenv.Source { return src }
	t.Cleanup(func() { hostSource = old })
}

// legacyOSRelease is tools/vulns.go osRelease before 1c.
func legacyOSRelease(b []byte) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			m[k] = strings.Trim(v, `"`)
		}
	}
	return m
}

func TestLegacyPlatform(t *testing.T) {
	for name, rp := range fixtures(t) {
		withHost(t, rp)
		raw, err := rp.ReadFile("/etc/os-release")
		if err != nil {
			t.Fatal(err)
		}
		kernel, _ := rp.ReadFile("/proc/sys/kernel/osrelease")
		want := legacyOSRelease(raw)
		plat, got := hostPlatform()
		for _, k := range []string{"ID", "VERSION_ID", "VERSION", "PRETTY_NAME", "ID_LIKE"} {
			if got[k] != want[k] {
				t.Errorf("%s %s: %q, legacy %q", name, k, got[k], want[k])
			}
		}
		if plat.PrettyName != want["PRETTY_NAME"] || plat.Kernel != strings.TrimSpace(string(kernel)) {
			t.Errorf("%s: platform %+v", name, plat)
		}
	}
}
