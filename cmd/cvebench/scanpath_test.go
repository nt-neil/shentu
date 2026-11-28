package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// writeTree writes files (path from dir → content) under dir.
func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for p, src := range files {
		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, p), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// acrossFiles has a request read in app/views.py and the shell command in
// app/run.py: no file shows the flow on its own.
var acrossFiles = map[string]string{
	"app/views.py": "from flask import Flask, request\nfrom .run import run_tool\n\napp = Flask(__name__)\n\n\n" +
		"@app.route(\"/tool\")\ndef tool():\n    return run_tool(request.args.get(\"name\", \"\"))\n",
	"app/run.py": "import os\n\n\ndef run_tool(name):\n    os.system(\"tool --name \" + name)\n    return \"ok\"\n",
}

func testEngine(t *testing.T) *engine.Engine {
	t.Helper()
	rs, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(rs)
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

// A flow found only by following the call into another file: the product path
// keeps the calls-across-files half (as app_code_audit merges it), so it
// reports, as the project path does; the per-file path cannot.
func TestScanPathCallsAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, acrossFiles)
	eng := testEngine(t)
	reported := func(path string) bool {
		for _, f := range scan(eng, dir, path).Findings {
			if f.RuleID == "python-cmdi-shell" && f.Path == "app/run.py" && f.Line == 5 {
				return true
			}
		}
		return false
	}
	if !reported(pathProduct) {
		t.Error("product path: the command built in another file is not reported")
	}
	if !reported(pathProject) {
		t.Error("project path: the command built in another file is not reported")
	}
	if reported(pathPerFile) {
		t.Error("per-file path: reported a flow it cannot see")
	}
}

// The product path counts a file whose calls a cap cut short (calls cut) and
// one a clock cut short (Clock, listed in the report).
func TestScanPathCutCounts(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, acrossFiles)
	eng := testEngine(t)
	saved := projectOptions
	defer func() { projectOptions = saved }()

	projectOptions.MaxHeap = 1 // the heap cap stops following the calls
	if r := scan(eng, dir, pathProduct); r.CallsCut == 0 {
		t.Errorf("MaxHeap 1: no file counted as calls cut: %+v", r)
	}

	projectOptions = saved
	projectOptions.MaxTime = time.Nanosecond
	r := scan(eng, dir, pathProduct)
	if r.Clock == 0 {
		t.Fatalf("MaxTime 1ns: no file counted as cut by a clock: %+v", r)
	}
	md := markdown([]caseResult{{Case: Case{ID: "CVE-2000-0001"}, Vuln: r}}, nil, time.Unix(0, 0), "")
	if !strings.Contains(md, "## Cut by a clock") || !strings.Contains(md, "| CVE-2000-0001 | ") {
		t.Errorf("the report does not list the clocked case:\n%s", md)
	}
}

// A calls pass that a cap cut short without an error of its own counts as calls
// cut; its own error is kept.
func TestCallsErr(t *testing.T) {
	if err := callsErr(engine.CallsPart{Cut: true}, nil); !errors.Is(err, engine.ErrCalls) {
		t.Errorf("cut, no error: got %v, want ErrCalls", err)
	}
	if err := callsErr(engine.CallsPart{}, nil); err != nil {
		t.Errorf("not cut: got %v", err)
	}
	if err := callsErr(engine.CallsPart{Cut: true}, engine.ErrLimit); !errors.Is(err, engine.ErrLimit) {
		t.Errorf("cut with ErrLimit: got %v", err)
	}
}

// A calls pass a cap cut short without an error of its own counts as calls cut
// in a release's scan (S-283-5): a stand-in ScanCallsPart returns Cut, no error.
func TestScanCountsCutCallsPass(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, acrossFiles)
	saved := newScanner
	defer func() { newScanner = saved }()
	newScanner = func(*engine.Engine, []string, func(string) ([]byte, error), string, engine.ProjectOptions) (func(string, []byte) scanned, func() bool, bool) {
		return productScan(func(string, []byte) ([]engine.Finding, bool, error) { return nil, false, nil },
			func(rel string, _ []byte) (engine.CallsPart, error) {
				return engine.CallsPart{Cut: rel == "app/views.py"}, nil
			}), func() bool { return false }, true
	}
	r := scan(testEngine(t), dir, pathProduct)
	if r.CallsCut != 1 || r.Unfinished != 0 || r.Clock != 0 {
		t.Errorf("calls cut %d, unfinished %d, clock %d; want 1, 0, 0", r.CallsCut, r.Unfinished, r.Clock)
	}
}
