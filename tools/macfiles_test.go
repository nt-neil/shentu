package tools

import (
	"context"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"
)

// M0: on macOS a file whose mtime was set back is found by its ctime, with
// its owner's name from dscl (runs on macOS, the CI macos job).
func TestMacFileChangesCtimeOwner(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "planted")
	os.WriteFile(p, []byte("x"), 0o600)
	old := time.Now().Add(-48 * time.Hour)
	os.Chtimes(p, old, old) // a faked mtime; ctime is now
	tool, _ := Find("file_changes")
	out, err := tool.Run(context.Background(), &Env{WatchPaths: []string{dir}}, json.RawMessage(`{"since_hours":1}`))
	if err != nil {
		t.Fatal(err)
	}
	files, _ := out.(map[string]any)["files"].([]Changed)
	me, _ := user.Current()
	if len(files) != 1 || files[0].Owner != me.Username {
		t.Errorf("files: %+v (owner want %q)", files, me.Username)
	}
}

// M0: a directory that cannot be read is listed as unread, not taken as
// unchanged.
func TestFileChangesUnread(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a non-root unix user")
	}
	dir := t.TempDir()
	closed := filepath.Join(dir, "closed")
	os.Mkdir(closed, 0o700)
	os.WriteFile(filepath.Join(closed, "f"), []byte("x"), 0o600)
	os.Chmod(closed, 0)
	t.Cleanup(func() { os.Chmod(closed, 0o700) })
	tool, _ := Find("file_changes")
	out, err := tool.Run(context.Background(), &Env{WatchPaths: []string{dir}}, json.RawMessage(`{"since_hours":1}`))
	if err != nil {
		t.Fatal(err)
	}
	unread, _ := out.(map[string]any)["unread"].([]string)
	if !slices.Contains(unread, closed) {
		t.Errorf("unread: %v", unread)
	}
}

// M0: certbot's certificates are looked for in Homebrew's places too.
func TestCertbotGlobsHomebrew(t *testing.T) {
	for _, g := range []string{"/opt/homebrew/etc/letsencrypt/live/*/cert.pem", "/usr/local/etc/letsencrypt/live/*/cert.pem", "/etc/letsencrypt/live/*/cert.pem"} {
		if !slices.Contains(certbotGlobs, g) {
			t.Errorf("missing %s", g)
		}
	}
}

// N-183-2: a watched root that is a link (macOS's /etc) is walked where it
// leads, and its files are shown under the root as set.
func TestFileChangesSymlinkRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix links")
	}
	dir := t.TempDir()
	real := filepath.Join(dir, "private", "etc")
	os.MkdirAll(real, 0o755)
	os.WriteFile(filepath.Join(real, "planted"), []byte("x"), 0o600)
	link := filepath.Join(dir, "etc")
	os.Symlink(real, link)
	tool, _ := Find("file_changes")
	out, err := tool.Run(context.Background(), &Env{WatchPaths: []string{link}}, json.RawMessage(`{"since_hours":1}`))
	if err != nil {
		t.Fatal(err)
	}
	files, _ := out.(map[string]any)["files"].([]Changed)
	if len(files) != 1 || files[0].Path != filepath.Join(link, "planted") {
		t.Errorf("files under a linked root: %+v", files)
	}
}

// S-183-1: a watched path this host does not have is missing, not unread.
func TestFileChangesMissingNotUnread(t *testing.T) {
	gone := filepath.Join(t.TempDir(), "no-such-dir")
	tool, _ := Find("file_changes")
	out, err := tool.Run(context.Background(), &Env{WatchPaths: []string{gone}}, json.RawMessage(`{"since_hours":1}`))
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	if missing, _ := m["missing"].([]string); !slices.Equal(missing, []string{gone}) || m["unread"] != nil {
		t.Errorf("missing %v, unread %v", m["missing"], m["unread"])
	}
}
