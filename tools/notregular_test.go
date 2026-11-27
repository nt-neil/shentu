//go:build !windows

package tools

import (
	"context"
	"io/fs"
	"slices"
	"strings"
	"testing"
)

// S-257-3: a file the audit, the lock-file search or the plugin search
// would read that is no regular file (a FIFO, a device, a cloud or HSM
// placeholder) is said not checked, never a quiet gap; a link (not
// followed by design) and a name none of them reads are not.
func TestNotRegularSaid(t *testing.T) {
	const r = "/srv/notreg-example"
	h := treeHost{files: map[string]string{
		r + "/site/index.php":                          "<?php echo 1;\n",
		r + "/site/fifo.php":                           "",
		r + "/site/placeholder.js":                     "",
		r + "/site/run.sock":                           "", // a name the audit does not read
		r + "/site/linked.php":                         "",
		r + "/app/package-lock.json":                   "",
		r + "/site/wp-content/plugins/cloud/cloud.php": "",
	}, links: map[string]string{r + "/site/linked.php": r + "/elsewhere.php"},
		mode: map[string]fs.FileMode{
			r + "/site/fifo.php":                           fs.ModeNamedPipe | 0o644,
			r + "/site/placeholder.js":                     fs.ModeIrregular,
			r + "/site/run.sock":                           fs.ModeSocket | 0o755,
			r + "/app/package-lock.json":                   fs.ModeIrregular,
			r + "/site/wp-content/plugins/cloud/cloud.php": fs.ModeIrregular,
		}}
	withHost(t, h)

	res := AppCodeAudit(context.Background(), []string{r + "/site"}, []string{r + "/site"})
	note := strings.Join(res.NotChecked, "\n")
	if !strings.Contains(note, "3 file(s) are not regular files (a FIFO, a device, a cloud or HSM placeholder), not audited") ||
		!strings.Contains(note, r+"/site/fifo.php") || !strings.Contains(note, r+"/site/placeholder.js") || strings.Contains(note, "run.sock") || strings.Contains(note, "linked.php") {
		t.Errorf("code audit not checked: %q", res.NotChecked)
	}
	if res.Files == 0 {
		t.Errorf("index.php not audited")
	}

	if ls, skipped := findLockfiles([]string{r}); len(ls) != 0 || skipped.noteZh("沒有檢查") != "1 個檔案不是一般檔案（FIFO、裝置檔，或 cloud、HSM 的 placeholder），沒有檢查："+r+"/app/package-lock.json" {
		t.Errorf("lock files %+v, note %q", ls, skipped.noteZh("沒有檢查"))
	}

	if _, unread := WordPressPlugins([]string{r + "/site"}); !slices.ContainsFunc(unread, func(u string) bool {
		return strings.Contains(u, "cloud.php: not a regular file (a FIFO, a device, a cloud or HSM placeholder), not read")
	}) {
		t.Errorf("plugins unread %q", unread)
	}
}

// More than three are counted, three named.
func TestNotRegularNoteCut(t *testing.T) {
	var c notRegularCount
	for _, p := range []string{"/a", "/b", "/c", "/d", "/e"} {
		c.add(p)
	}
	if got := c.note("not audited"); got != "5 file(s) are not regular files (a FIFO, a device, a cloud or HSM placeholder), not audited: /a, /b, /c and 2 more" {
		t.Errorf("%q", got)
	}
	if (&notRegularCount{}).note("x") != "" {
		t.Error("a note with none")
	}
}

// S-279-2: app_vulns' partial says it in Chinese, as its other notes.
func TestNotRegularNoteZh(t *testing.T) {
	var c notRegularCount
	for _, p := range []string{"/a", "/b", "/c", "/d"} {
		c.add(p)
	}
	if got := c.noteZh("沒有檢查"); got != "4 個檔案不是一般檔案（FIFO、裝置檔，或 cloud、HSM 的 placeholder），沒有檢查：/a、/b、/c，另外還有 1 個" {
		t.Errorf("%q", got)
	}
}
