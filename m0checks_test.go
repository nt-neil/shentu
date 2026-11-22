package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
	"github.com/nt-neil/shentu/tools"
)

func checksOn(t *testing.T, src hostenv.Source, st *state) ([]finding, string) {
	return checksOnEnv(t, src, st, &tools.Env{})
}

func checksOnEnv(t *testing.T, src hostenv.Source, st *state, env *tools.Env) ([]finding, string) {
	t.Helper()
	t.Cleanup(tools.SetHostSourceForTest(src))
	cfg := &Config{StateDir: t.TempDir()}
	cfg.Patrol.SSHThreshold = 10
	out, why := checks(context.Background(), cfg, env, st, false)
	return out, uncheckedSection(st.Profile.Risks) + why
}

// N-177-1, S-177-1, N-180-1 through the patrol's own entry: on a macOS host
// where nothing can be read, the report lists the listening services, the
// processes and the accounts as not checked, and finds nothing as if the
// host were clean.
func TestChecksMacOSUnreadable(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"format":"`+hostenv.FixtureFormat+`","info":{"goos":"darwin","goarch":"arm64"},"entries":[]}`), 0o600)
	os.Mkdir(filepath.Join(dir, "blobs"), 0o700)
	rp, err := hostenv.LoadReplay(dir)
	if err != nil {
		t.Fatal(err)
	}
	st := &state{}
	_, unchecked := checksOn(t, rp, st)
	for _, want := range []string{"cannot tell the listening services", "Not checked: processes", "Not checked: accounts", "cannot tell the login accounts"} {
		if !strings.Contains(unchecked, want) {
			t.Errorf("not checked lacks %q:\n%s", want, unchecked)
		}
	}
	if st.Ports != nil || st.PortsV != 0 {
		t.Errorf("a baseline was made from an unread table: %v v%d", st.Ports, st.PortsV)
	}
}

// N-177-2 through the patrol's entry: a macOS state saved before M0
// ({"ports":{}}) takes the first good read as the baseline, with no port
// warning; the second run warns of nothing either.
func TestChecksMacOSBaselineFromEmpty(t *testing.T) {
	rp, err := hostenv.LoadReplay("hostenv/testdata/darwin/macos27-synthetic-user")
	if err != nil {
		t.Fatal(err)
	}
	st := &state{Ports: map[string]bool{}}
	for run := 1; run <= 2; run++ {
		out, _ := checksOn(t, rp, st)
		for _, f := range out {
			if strings.HasPrefix(f.Key, "port:") {
				t.Errorf("run %d: %s", run, f.Summary)
			}
		}
	}
	if len(st.Ports) != 3 || st.PortsV != portsBaselineV {
		t.Errorf("baseline: %v v%d", st.Ports, st.PortsV)
	}
}

// N-183-1 through the patrol's entry: watched paths that cannot be read
// are in the report's "not checked".
func TestChecksFileChangesUnread(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a non-root unix user")
	}
	closed := filepath.Join(t.TempDir(), "closed")
	os.Mkdir(closed, 0o700)
	os.Mkdir(filepath.Join(closed, "sub"), 0o700)
	os.Chmod(filepath.Join(closed, "sub"), 0)
	t.Cleanup(func() { os.Chmod(filepath.Join(closed, "sub"), 0o700) })
	rp, err := hostenv.LoadReplay("hostenv/testdata/darwin/macos27-synthetic-user")
	if err != nil {
		t.Fatal(err)
	}
	_, unchecked := checksOnEnv(t, rp, &state{}, &tools.Env{WatchPaths: []string{closed}})
	if !strings.Contains(unchecked, "Not checked: file changes under 1 paths") {
		t.Errorf("not checked:\n%s", unchecked)
	}
}
