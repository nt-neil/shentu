//go:build !windows

package tools

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// N-279-1: a lock file that is a FIFO is said in partial, and that does not
// make the site-packages walk look incomplete: setuptools' own
// distutils-precedence.pth is still known as setuptools'.
func TestNotRegularLockKeepsPthKnown(t *testing.T) {
	noSystemSitePackages(t)
	root := t.TempDir()
	sp := venvSite(t, root, "app")
	pth := "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); \n"
	os.WriteFile(filepath.Join(sp, "distutils-precedence.pth"), []byte(pth), 0o644)
	dist(t, sp, "setuptools-69.0.0", "setuptools", "69.0.0", "pip")
	record(t, sp, "setuptools-69.0.0", "_distutils_hack/__init__.py", "def add_shim(): pass\n")
	record(t, sp, "setuptools-69.0.0", "distutils-precedence.pth", pth)
	other := filepath.Join(root, "web")
	os.MkdirAll(other, 0o755)
	if err := syscall.Mkfifo(filepath.Join(other, "package-lock.json"), 0o644); err != nil {
		t.Skip("no FIFO here:", err)
	}
	out, err := appVulnsIn(context.Background(), &http.Client{Transport: &pypiFeeds{}}, []string{root}, false)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := out["partial"].(string); !strings.Contains(p, "1 個檔案不是一般檔案") || !strings.Contains(p, "package-lock.json") {
		t.Errorf("partial %q", p)
	}
	ps, _ := out["pth"].([]PthFile)
	// told as setuptools' (Known, or Unproven in a folder its user can
	// write, as this temporary one): not cleared to "one to look at"
	if len(ps) != 1 || ps[0].Known != "setuptools" && ps[0].Unproven != "setuptools" {
		t.Errorf("pth %+v: want setuptools' own told", ps)
	}
}
