//go:build windows

package tools

import (
	"context"
	"net/http"
	"testing"
)

// P (Windows CI run 45916176878): a genuine setuptools distutils-precedence.pth
// in a Windows venv is setuptools' (Unproven: its RECORD lists it; a user's
// folder), never one to look at. On the base, recordHas globbed the Windows
// path with POSIX-only hostenv.Glob, found no RECORD, and listed it.
func TestSitePackagesPthWindowsVenv(t *testing.T) {
	noSystemSitePackages(t)
	root := t.TempDir()
	sp := venvSite(t, root, "app")
	pth := "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); \n"
	dist(t, sp, "setuptools-69.0.0", "setuptools", "69.0.0", "pip")
	record(t, sp, "setuptools-69.0.0", "_distutils_hack/__init__.py", "def add_shim(): pass\n")
	record(t, sp, "setuptools-69.0.0", "distutils-precedence.pth", pth)
	out, err := AppVulns(context.Background(), &http.Client{Transport: &pypiFeeds{}}, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	ps, _ := out["pth"].([]PthFile)
	if len(ps) != 1 || ps[0].Unproven != "setuptools" && ps[0].Known != "setuptools" {
		t.Errorf("the venv's distutils-precedence.pth: %+v, want setuptools' (not one to look at)", ps)
	}
}
