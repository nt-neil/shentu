package tools

import (
	"context"
	"io/fs"
	"sort"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// treeHost is a host source holding a made-up tree in memory: files,
// links, and the folders above them. Nothing of it is on the machine
// running the test, so a check reading the machine finds none of it.
type treeHost struct {
	files map[string]string
	links map[string]string
	uid   map[string]int         // owner, root's when not given
	mode  map[string]fs.FileMode // permission bits, 0644 (files) when not given
}

func (treeHost) Info() hostenv.SourceInfo { return hostenv.SourceInfo{GOOS: "linux"} }

func (h treeHost) isDir(p string) bool {
	for f := range h.files {
		if strings.HasPrefix(f, p+"/") {
			return true
		}
	}
	for l := range h.links {
		if strings.HasPrefix(l, p+"/") {
			return true
		}
	}
	return false
}

func (h treeHost) ReadFile(p string) ([]byte, error) {
	if t, ok := h.links[p]; ok {
		return h.ReadFile(t)
	}
	if s, ok := h.files[p]; ok {
		return []byte(s), nil
	}
	return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
}

func (h treeHost) ReadFileNoFollow(p string) ([]byte, error) {
	if _, ok := h.links[p]; ok {
		return nil, hostenv.ErrSymlink
	}
	return h.ReadFile(p)
}

func (h treeHost) ReadDir(p string) ([]string, error) {
	if !h.isDir(p) {
		return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
	}
	seen := map[string]bool{}
	for _, m := range []map[string]string{h.files, h.links} {
		for f := range m {
			if rest, ok := strings.CutPrefix(f, p+"/"); ok {
				seen[strings.SplitN(rest, "/", 2)[0]] = true
			}
		}
	}
	var out []string
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

func (h treeHost) Readlink(p string) (string, error) {
	if t, ok := h.links[p]; ok {
		return t, nil
	}
	return "", &fs.PathError{Op: "readlink", Path: p, Err: fs.ErrInvalid}
}

func (treeHost) Run(context.Context, []string) (hostenv.CmdResult, error) {
	return hostenv.CmdResult{}, fs.ErrNotExist
}

func (h treeHost) Lstat(p string) (hostenv.FileStat, error) {
	switch s, isFile := h.files[p]; {
	case h.links[p] != "":
		return hostenv.FileStat{Mode: fs.ModeSymlink | 0o777}, nil
	case isFile:
		m := fs.FileMode(0o644)
		if v, ok := h.mode[p]; ok {
			m = v
		}
		return hostenv.FileStat{Mode: m, Size: int64(len(s)), UID: h.uid[p]}, nil
	case h.isDir(p):
		return hostenv.FileStat{Mode: fs.ModeDir | 0o755}, nil
	}
	return hostenv.FileStat{}, &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrNotExist}
}

func (h treeHost) Stat(p string) (hostenv.FileStat, error) {
	if t, ok := h.links[p]; ok {
		return h.Stat(t)
	}
	return h.Lstat(p)
}

// S-280-1: a Linux host read's resumed audit orders and holds its paths by
// its own "/" on any machine: a Windows one split them at "\" and cleaned
// "/srv/www/" to "\srv\www", so the walk resumed in the wrong place.
func TestAuditResumePathsLinuxHost(t *testing.T) {
	withHost(t, treeHost{files: map[string]string{"/srv/www/a.php": ""}})
	if got := cleanRoots([]string{"/srv/www/", "/srv/app"}); got[0] != "/srv/www" || got[1] != "/srv/app" {
		t.Errorf("cleanRoots %q", got)
	}
	sep := hostPaths().Sep
	for _, c := range []struct {
		a, b string
		want int // sign
	}{
		{"/srv/www", "/srv/www/a.php", -1}, // a folder before what it holds
		{"/srv/www/b", "/srv/www-old", -1}, // name by name: "www" < "www-old"
		{"/srv/www/a.php", "/srv/www/a.php", 0},
	} {
		if got := pathCmp(c.a, c.b, sep); got < 0 != (c.want < 0) || got == 0 != (c.want == 0) {
			t.Errorf("pathCmp(%q, %q) = %d, want sign %d", c.a, c.b, got, c.want)
		}
	}
	if !walkHolds("/srv/www", "/srv/www/x/y.php", sep) || walkHolds("/srv/www", "/srv/www-old/x", sep) {
		t.Error("walkHolds with a Linux host's paths")
	}
}
