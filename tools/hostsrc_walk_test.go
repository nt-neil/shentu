//go:build !windows

package tools

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// The walks of app_code_audit, app_vulns (lock files, site-packages) and
// the WordPress plugin search read the host source (host-source PR-2b):
// on a replay or another host's survey, the machine running the check is
// never what answers. Made-up names and versions.
func TestWalkChecksReadHostSource(t *testing.T) {
	const r = "/srv/hostsrc-example"
	h := treeHost{files: map[string]string{
		r + "/app/composer.lock":                                                   `{"packages":[{"name":"guzzlehttp/guzzle","version":"7.4.0"}]}`,
		r + "/app/node_modules/x/package-lock.json":                                `{}`, // skipped folder
		r + "/site/info.php":                                                       "<?php\nphpinfo();\n",
		r + "/site/wp-content/plugins/hello/hello.php":                             "<?php\n/*\nPlugin Name: Hello Example\nVersion: 1.2\n*/\n",
		r + "/venv/lib/python3.12/site-packages/requests-2.0.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: requests\nVersion: 2.0.0\n\n",
		r + "/elsewhere/real.php":                                                  "<?php\n/*\nPlugin Name: Linked\n*/\n",
	}, links: map[string]string{
		r + "/site/wp-content/plugins/linked": r + "/elsewhere",
	}}
	withHost(t, h)

	ls := FindLockfiles([]string{r})
	if len(ls) != 1 || ls[0].Path != r+"/app/composer.lock" || len(ls[0].pkgs) != 1 || ls[0].pkgs[0].Name != "guzzlehttp/guzzle" {
		t.Errorf("lock files %+v", ls)
	}

	ps, unread := WordPressPlugins([]string{r + "/site"})
	if len(ps) != 1 || ps[0].Name != "Hello Example" || ps[0].Version != "1.2" || ps[0].Slug != "hello" {
		t.Errorf("plugins %+v", ps)
	}
	if !slices.Contains(unread, r+"/site/wp-content/plugins/linked (a link, not followed)") {
		t.Errorf("a linked plugin not said: %q", unread)
	}

	dirs, notes := findSitePackages([]string{r}, false)
	if want := r + "/venv/lib/python3.12/site-packages"; !slices.Equal(dirs, []string{want}) || len(notes) != 0 {
		t.Fatalf("site-packages %q %q", dirs, notes)
	}
	if sd := readSitePackages(dirs[0]); len(sd.pkgs) != 1 || sd.pkgs[0] != (pkg{"requests", "2.0.0"}) {
		t.Errorf("site-packages read %+v", sd)
	}

	res := AppCodeAudit(context.Background(), []string{r + "/site"}, []string{r + "/site"})
	if !slices.ContainsFunc(res.Findings, func(f CodeFinding) bool { return f.Kind == "exposed" && f.Path == r+"/site/info.php" }) ||
		res.Files == 0 || len(res.NotChecked) != 0 {
		t.Errorf("code audit: files %d, findings %+v, not checked %q", res.Files, res.Findings, res.NotChecked)
	}
}

// A replay of a fixture recorded before lstat was (or that lacks the web
// root): the root is said unread, not audited, never an audit of nothing
// taken for a clean one.
func TestCodeAuditOldFixtureUnread(t *testing.T) {
	rp, err := hostenv.LoadReplay(path.Join("..", "hostenv", "testdata", "linux", "debian12-root"))
	if err != nil {
		t.Fatal(err)
	}
	withHost(t, rp)
	res := AppCodeAudit(context.Background(), []string{"/var/www/example"}, nil)
	if want := "/var/www/example could not be read (hostenv: not in fixture): not audited"; !slices.Equal(res.NotChecked, []string{want}) || res.Files != 0 {
		t.Errorf("not checked %q, files %d; want %q", res.NotChecked, res.Files, want)
	}
	if _, err := hostenv.Lstat(rp, "/var/www/example"); !errors.Is(err, hostenv.ErrNotRecorded) {
		t.Errorf("lstat %v", err)
	}
}

// rootOnlyFile reads the owner and mode through the host source: root's
// alone only when root owns it and no one else may write it.
func TestRootOnlyFileHostSource(t *testing.T) {
	const d = "/srv/hostsrc-example/lib"
	withHost(t, treeHost{files: map[string]string{d + "/root.py": "", d + "/user.py": "", d + "/open.py": ""},
		uid: map[string]int{d + "/user.py": 1000}, mode: map[string]fs.FileMode{d + "/open.py": 0o666}})
	for f, want := range map[string]bool{"root.py": true, "user.py": false, "open.py": false, "none.py": false} {
		if got := rootOnlyFile(d+"/"+f, false); got != want {
			t.Errorf("%s: root's alone %v, want %v", f, got, want)
		}
	}
	if !rootOnlyFile(d, true) || rootOnlyFile(d+"/root.py", true) {
		t.Errorf("a folder: root's alone only as a folder")
	}
}

// countHost counts ReadDir and ReadDirMax; a folder in cut gives "more"
// past its first name, one in denied is unreadable.
type countHost struct {
	treeHost
	dirs, dirMax *int
	cut, denied  map[string]bool
}

func (h countHost) ReadDir(p string) ([]string, error) {
	*h.dirs++
	if h.denied[p] {
		return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrPermission}
	}
	return h.treeHost.ReadDir(p)
}

// Lstat of what is under a denied folder is denied too, as on a host.
func (h countHost) Lstat(p string) (hostenv.FileStat, error) {
	for d := range h.denied {
		if strings.HasPrefix(p, d+"/") {
			return hostenv.FileStat{}, &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrPermission}
		}
	}
	return h.treeHost.Lstat(p)
}

func (h countHost) ReadDirMax(p string, n int) ([]string, bool, error) {
	*h.dirMax++
	if h.denied[p] {
		return nil, false, &fs.PathError{Op: "open", Path: p, Err: fs.ErrPermission}
	}
	names, err := h.treeHost.ReadDir(p)
	if h.cut[p] && len(names) > 1 {
		return names[:1], true, err
	}
	return hostenv.ReadDirMax(h.treeHost, p, n)
}

// S-257-2: the plugin search reads folders through ReadDirMax only (a web
// folder a user fills is never read whole); a folder cut, or a root not
// read, is said once (nit: it was said twice).
func TestWordPressPluginsDirMaxOnly(t *testing.T) {
	const r = "/srv/hostsrc-example/site"
	plugins := r + "/wp-content/plugins"
	var dirs, dirMax int
	h := countHost{treeHost: treeHost{files: map[string]string{
		plugins + "/aaa/aaa.php": "<?php\n/*\nPlugin Name: First Example\n*/\n",
		plugins + "/bbb/bbb.php": "<?php\n/*\nPlugin Name: Second Example\n*/\n",
	}}, dirs: &dirs, dirMax: &dirMax, cut: map[string]bool{plugins: true}}
	withHost(t, h)
	ps, unread := WordPressPlugins([]string{r})
	if dirs != 0 || dirMax == 0 {
		t.Errorf("ReadDir called %d times, ReadDirMax %d: want ReadDirMax only", dirs, dirMax)
	}
	if len(ps) != 1 || ps[0].Name != "First Example" {
		t.Errorf("plugins %+v, want the first one read", ps)
	}
	n := 0
	for _, u := range unread {
		if strings.HasPrefix(u, plugins+" (") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("the cut plugins folder said %d times, want once: %q", n, unread)
	}

	h.cut, h.denied = nil, map[string]bool{r: true}
	withHost(t, h)
	if _, unread := WordPressPlugins([]string{r}); len(unread) != 1 || unread[0] != r+" (open "+r+": permission denied)" {
		t.Errorf("an unreadable root: %q, want one line", unread)
	}
}
