package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nt-neil/shentu/rules"
	"github.com/nt-neil/shentu/rules/engine"
)

// A redirect target checked in another file (a base class's method, as
// taguette 1.5.2's sanitize_next_url): app_code_audit reads each file on its
// own first and keeps that finding, so the product path reports it; the project
// path follows the check into base.py and does not. The product path is what a
// user is shown, so it is the default.
func TestScanPathCheckInAnotherFile(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"app/base.py": "import re\nimport tornado.web\n\n\ndef is_safe(url, base):\n" +
			"    return url and re.match(re.escape(base) + r\"/[a-z][a-z0-9/_-]*$\", url)\n\n\n" +
			"class BaseHandler(tornado.web.RequestHandler):\n    def clean_next(self, url):\n" +
			"        if is_safe(url, \"/app\"):\n            return url\n        return self.reverse_url(\"index\")\n",
		"app/views.py": "from .base import BaseHandler\n\n\nclass LoginHandler(BaseHandler):\n    def post(self):\n" +
			"        next_ = self.clean_next(self.get_argument(\"next\", \"\"))\n        return self.redirect(next_)\n",
	}
	for p, src := range files {
		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, p), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rs, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(rs)
	if err != nil {
		t.Fatal(err)
	}
	reported := func(path string) bool {
		for _, f := range scan(eng, dir, path).Findings {
			if f.RuleID == "python-open-redirect-redirect" && f.Path == "app/views.py" && f.Line == 7 {
				return true
			}
		}
		return false
	}
	if !reported(pathProduct) {
		t.Error("product path: the redirect is not reported, but app_code_audit reports it")
	}
	if reported(pathProject) {
		t.Error("project path: the redirect is reported, though the check in base.py holds")
	}
	if !reported(pathPerFile) {
		t.Error("per-file path: the redirect is not reported")
	}
}
