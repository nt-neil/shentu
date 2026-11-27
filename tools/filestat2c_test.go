package tools

import (
	"context"
	"encoding/json"
	"io/fs"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

// statHost is a host read with stats as set: files (content), their stats,
// folders implied by the paths, an error per path. Made-up paths.
type statHost struct {
	files map[string]string
	stat  map[string]hostenv.FileStat
	errs  map[string]error
}

func (statHost) Info() hostenv.SourceInfo { return hostenv.SourceInfo{GOOS: "linux", GOARCH: "arm64"} }
func (h statHost) isDir(p string) bool {
	for f := range h.files {
		if strings.HasPrefix(f, p+"/") {
			return true
		}
	}
	return false
}
func (h statHost) ReadFile(p string) ([]byte, error) {
	if s, ok := h.files[p]; ok {
		return []byte(s), nil
	}
	return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
}
func (h statHost) ReadDir(p string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for f := range h.files {
		if rest, ok := strings.CutPrefix(f, p+"/"); ok {
			n := strings.SplitN(rest, "/", 2)[0]
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	if len(out) == 0 {
		return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
	}
	return out, nil
}
func (h statHost) Readlink(p string) (string, error) {
	if _, err := h.Lstat(p); err != nil { // as readlink(2): ENOENT for a path not there
		return "", err
	}
	return "", &fs.PathError{Op: "readlink", Path: p, Err: fs.ErrInvalid}
}
func (statHost) Run(context.Context, []string) (hostenv.CmdResult, error) {
	return hostenv.CmdResult{}, fs.ErrNotExist
}
func (h statHost) Lstat(p string) (hostenv.FileStat, error) {
	if err := h.errs[p]; err != nil {
		return hostenv.FileStat{}, err
	}
	if st, ok := h.stat[p]; ok {
		return st, nil
	}
	if h.isDir(p) {
		return hostenv.FileStat{Mode: fs.ModeDir | 0o755}, nil
	}
	if s, ok := h.files[p]; ok {
		return hostenv.FileStat{Mode: 0o644, Size: int64(len(s))}, nil
	}
	return hostenv.FileStat{}, &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrNotExist}
}
func (h statHost) Stat(p string) (hostenv.FileStat, error) { return h.Lstat(p) }

// PR-2c: file_changes walks the host read: a file whose mtime was set back
// but whose ctime is new is changed, its owner named from the host's
// accounts, its webshell found in what the host source gives; what could
// not be read is said.
func TestFileChangesHostSource(t *testing.T) {
	if runtime.GOOS == "windows" {
		// A Linux host read on a Windows machine: hostenv.Walk and the log
		// allowlist join and match with filepath (\ there), S-272-2's
		// class (plan PR-3); the Windows host read is not what this tests.
		t.Skip("a Linux host read's paths, joined by filepath on Windows (PR-3)")
	}
	now := time.Now()
	old := now.Add(-72 * time.Hour)
	recent := now.Add(-10 * time.Minute)
	reg := func(size int, uid int, mt time.Time, ct *time.Time) hostenv.FileStat {
		n := uint64(1)
		return hostenv.FileStat{Mode: 0o644, Size: int64(size), ModTime: mt, UID: uid, CTime: ct, NLink: &n}
	}
	shell := "<?php system($_GET['c']); ?>"
	withHost(t, statHost{
		files: map[string]string{
			"/etc/passwd":             "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
			"/srv/site/up/x.php":      shell,
			"/srv/site/stale.txt":     "s",
			"/srv/site/locked/secret": "",
		},
		stat: map[string]hostenv.FileStat{
			"/srv/site/up/x.php":  reg(len(shell), 33, old, &recent), // mtime faked back, ctime not
			"/srv/site/stale.txt": reg(1, 0, old, &old),
		},
		errs: map[string]error{"/srv/site/locked": &fs.PathError{Op: "lstat", Path: "/srv/site/locked", Err: fs.ErrPermission}},
	})
	out, err := FileChanges(context.Background(), []string{"/srv/site", "/srv/none"}, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	files, _ := out["files"].([]Changed)
	if len(files) != 1 || files[0].Path != "/srv/site/up/x.php" || files[0].Owner != "www-data" || !files[0].Modified.Equal(recent) || len(files[0].Webshell) == 0 {
		b, _ := json.Marshal(out)
		t.Fatalf("changed files: %s", b)
	}
	if u, _ := out["unread"].([]string); len(u) != 1 || u[0] != "/srv/site/locked" {
		t.Errorf("unread %v", out["unread"])
	}
	if m, _ := out["missing"].([]string); len(m) != 1 || m[0] != "/srv/none" {
		t.Errorf("missing %v", out["missing"])
	}
}

// PR-2c: log_search's hard-link check reads the host's link count; one
// not known (an older fixture) is not judged.
func TestLogSearchHardLinkHostSource(t *testing.T) {
	if runtime.GOOS == "windows" {
		// A Linux host read on a Windows machine: hostenv.Walk and the log
		// allowlist join and match with filepath (\ there), S-272-2's
		// class (plan PR-3); the Windows host read is not what this tests.
		t.Skip("a Linux host read's paths, joined by filepath on Windows (PR-3)")
	}
	two, one := uint64(2), uint64(1)
	for name, c := range map[string]struct {
		nlink  *uint64
		refuse bool
	}{"two links": {&two, true}, "one link": {&one, false}, "not known": {nil, false}} {
		withHost(t, statHost{
			files: map[string]string{"/var/log/app.log": "Failed password for root\n"},
			stat:  map[string]hostenv.FileStat{"/var/log/app.log": {Mode: 0o640, Size: 25, ModTime: time.Now(), NLink: c.nlink}},
		})
		_, err := logSearch.Run(context.Background(), &Env{LogPaths: []string{"/var/log/*.log"}}, json.RawMessage(`{"path":"/var/log/app.log","pattern":"Failed"}`))
		if refused := err != nil && strings.Contains(err.Error(), "hard links"); refused != c.refuse {
			t.Errorf("%s: err %v", name, err)
		}
	}
}
