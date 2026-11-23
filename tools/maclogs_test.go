package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// M0 PR4: only macOS's three system links map back; any other path stays.
func TestMacUnprivate(t *testing.T) {
	for in, want := range map[string]string{
		"/private/var/log/system.log": "/var/log/system.log", "/private/etc/ssh/sshd_config": "/etc/ssh/sshd_config",
		"/private/tmp/a.log": "/tmp/a.log", "/private/varx/a.log": "/private/varx/a.log",
		"/private/Users/a.log": "/private/Users/a.log", "/var/log/system.log": "/var/log/system.log",
	} {
		if got := macUnprivate(in); got != want {
			t.Errorf("macUnprivate(%q) = %q, want %q", in, got, want)
		}
	}
}

// M0 PR4: on macOS a log under /var (a link to /private/var) is searched
// by the path log_paths names; a link out of the log directory is still
// refused. t.TempDir is under /var/folders there.
func TestLogSearchMacVarLink(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only: /var is a link to /private/var")
	}
	dir := t.TempDir()
	if real, _ := filepath.EvalSymlinks(dir); !strings.HasPrefix(dir, "/var/") || real != "/private"+dir {
		t.Skipf("temp dir %s is not under the /var link", dir)
	}
	os.WriteFile(filepath.Join(dir, "a.log"), []byte("one sshd line\nother\n"), 0o644)
	outside := filepath.Join(t.TempDir(), "x")
	os.MkdirAll(outside, 0o755)
	os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("sshd secret\n"), 0o644)
	os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(dir, "b.log"))
	env := &Env{LogPaths: []string{filepath.Join(dir, "*.log")}}
	run := func(name string) (any, error) {
		args, _ := json.Marshal(map[string]any{"pattern": "sshd", "path": filepath.Join(dir, name)})
		return logSearch.Run(context.Background(), env, args)
	}
	r, err := run("a.log")
	if err != nil {
		t.Fatalf("a.log refused: %v", err)
	}
	if m := r.(map[string]any)["matches"].([]string); len(m) != 1 || m[0] != "one sshd line" {
		t.Errorf("matches: %v", m)
	}
	if _, err := run("b.log"); err == nil || !strings.Contains(err.Error(), "outside the allowed") {
		t.Errorf("a link out of the log directory was read: %v", err)
	}
}

// S-186-1: a log file with a second hard link (a root-only file linked
// into a log directory looks the same) is refused.
func TestLogSearchHardLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix hard links")
	}
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	other, _ := filepath.EvalSymlinks(t.TempDir())
	os.WriteFile(filepath.Join(other, "secret"), []byte("sshd secret\n"), 0o600)
	if err := os.Link(filepath.Join(other, "secret"), filepath.Join(dir, "a.log")); err != nil {
		t.Skip(err)
	}
	os.WriteFile(filepath.Join(dir, "b.log"), []byte("sshd ok\n"), 0o600)
	env := &Env{LogPaths: []string{filepath.Join(dir, "*.log")}}
	run := func(name string) error {
		args, _ := json.Marshal(map[string]any{"pattern": "sshd", "path": filepath.Join(dir, name)})
		_, err := logSearch.Run(context.Background(), env, args)
		return err
	}
	if err := run("a.log"); err == nil || !strings.Contains(err.Error(), "hard links") {
		t.Errorf("hard-linked a.log: %v", err)
	}
	if err := run("b.log"); err != nil {
		t.Errorf("b.log: %v", err)
	}
}
