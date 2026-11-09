package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/rules"
	"github.com/nt-neil/shentu/rules/engine"
)

func TestAppCodeAudit(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	pub := filepath.Join(dir, "site", "public")
	app := filepath.Join(dir, "site", "app")
	// Fake secrets are put together here so no real-looking key sits in the repository.
	awsKey := "AKIA" + strings.Repeat("Q7", 8)
	dbPass := "pa" + "ss" + "w0rdX"
	files := map[string]string{
		// should be found
		pub + "/.env":            "APP_KEY=x\n",
		pub + "/.git/HEAD":       "ref: refs/heads/main\n",
		pub + "/dump.sql":        "INSERT INTO users VALUES (1);\n",
		pub + "/site-backup.zip": "PK",
		pub + "/info.php":        "<?php\nphpinfo();\n",
		pub + "/uploads/cat.php": "<?php echo 1;\n",
		pub + "/shell.php":       "<?php\n\n@eval($_POST['x']);\n",
		app + "/settings.py":     "SECRET=1\nDEBUG = True\n",
		app + "/.env":            "APP_ENV=production\nAPP_DEBUG=true\n",
		app + "/run.py":          "from flask import Flask\napp = Flask(__name__)\napp.run(host='0.0.0.0', debug=True)\n",
		app + "/config.js":       "module.exports = {\n  key: '" + awsKey + "',\n}\n",
		app + "/db.py":           "URL = 'postgres://shop:" + dbPass + "@db/shop'\n",
		// should not be found
		dir + "/site/.env":         "APP_DEBUG=false\n",
		pub + "/.env.example":      "APP_KEY=\n",
		app + "/other/settings.py": "DEBUG = False\n",
		app + "/dev.py":            "# app.run(debug=True)\n",
		app + "/notes.md":          "remember phpinfo() and " + awsKey + "\n",
		pub + "/index.php":         "<?php echo htmlspecialchars($_GET['q']);\n",
	}
	for p, c := range files {
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res := AppCodeAudit(context.Background(), []string{filepath.Join(dir, "site")}, []string{pub})
	got := map[string]CodeFinding{}
	for _, f := range res.Findings {
		got[f.Kind+" "+strings.TrimPrefix(f.Path, dir+"/site/")] = f
	}
	want := map[string]string{ // kind + path → severity
		"exposed public/.env": "critical", "exposed public/.git": "critical", "exposed public/dump.sql": "critical",
		"exposed public/site-backup.zip": "warning", "exposed public/info.php": "warning",
		"upload_script public/uploads/cat.php": "critical", "webshell public/shell.php": "critical", "injection public/shell.php": "critical",
		"debug app/settings.py": "warning", "debug app/.env": "warning", "debug app/run.py": "critical",
		"secret app/config.js": "warning", "secret app/db.py": "warning",
	}
	for k, sev := range want {
		if f, ok := got[k]; !ok || f.Severity != sev {
			t.Errorf("%s: got %+v, want severity %s", k, f, sev)
		}
		delete(got, k)
	}
	for k := range got {
		t.Errorf("unexpected finding: %s", k)
	}
	if f := findingFor(res, "webshell", "shell.php"); f.Line != 3 {
		t.Errorf("webshell line = %d, want 3", f.Line)
	}
	if f := findingFor(res, "secret", "config.js"); f.Line != 2 || f.Fix == "" {
		t.Errorf("secret finding: %+v", f)
	}
	out, _ := json.Marshal(res)
	if strings.Contains(string(out), awsKey) || strings.Contains(string(out), dbPass) {
		t.Errorf("the audit result contains a secret value: %s", out)
	}
}

func findingFor(r CodeAudit, kind, base string) CodeFinding {
	for _, f := range r.Findings {
		if f.Kind == kind && filepath.Base(f.Path) == base {
			return f
		}
	}
	return CodeFinding{}
}

// Without web server configuration, public/ html/ www/ folders count as served.
func TestServedFallback(t *testing.T) {
	if !served("/srv/shop/public/.env", nil) || served("/srv/shop/.env", nil) {
		t.Error("fallback web folders are wrong")
	}
	if served("/var/www/shop/.env", nil) || !served("/var/www/html/.env", nil) || !served("/home/ann/www/.env", nil) {
		t.Error("/var/www itself must not count as served")
	}
	if served("/srv/shop/public/.env", []string{"/var/www/html"}) {
		t.Error("configured web roots must replace the fallback")
	}
}

func TestWebRootPatterns(t *testing.T) {
	nginx := "server {\n    root /var/www/shop/public;\n    # root /old;\n    location / { try_files $uri =404; }\n}\n"
	if m := nginxRoot.FindAllStringSubmatch(nginx, -1); len(m) != 1 || m[0][1] != "/var/www/shop/public" {
		t.Errorf("nginx root: %v", m)
	}
	apache := "<VirtualHost *:80>\n\tDocumentRoot \"/var/www/html\"\n</VirtualHost>\n"
	if m := apacheRoot.FindStringSubmatch(apache); m == nil || m[1] != "/var/www/html" {
		t.Errorf("apache root: %v", m)
	}
}

// Injection findings name the rule, the file and the line. One vulnerable sample per
// language comes from the rules themselves, so the test follows the rules.
func TestAppCodeAuditInjection(t *testing.T) {
	rs, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	ext := map[string]string{"php": ".php", "python": ".py", "js": ".jsx"}
	want := map[string]string{} // file name → rule id
	var code []string
	for _, r := range rs {
		if _, done := want["v"+ext[r.Lang]]; done {
			continue
		}
		for _, s := range r.Samples {
			if s.Kind == "vulnerable" {
				name := "v" + ext[r.Lang]
				os.WriteFile(filepath.Join(dir, name), []byte(s.Code), 0o644)
				want[name] = r.ID
				code = append(code, strings.TrimSpace(s.Code))
				break
			}
		}
	}
	// TypeScript files use the JavaScript rules.
	for _, r := range rs {
		for _, s := range r.Samples {
			if _, done := want["v.ts"]; !done && s.Kind == "vulnerable" && s.Dialect == "ts" {
				os.WriteFile(filepath.Join(dir, "v.ts"), []byte(s.Code), 0o644)
				want["v.ts"] = r.ID
				code = append(code, strings.TrimSpace(s.Code))
			}
		}
	}
	// Skipped folders stay skipped.
	os.MkdirAll(filepath.Join(dir, "vendor"), 0o755)
	os.WriteFile(filepath.Join(dir, "vendor", "v.php"), []byte("<?php\neval($_GET['c']);\n"), 0o644)
	res := AppCodeAudit(context.Background(), []string{dir}, nil)
	for name, id := range want {
		f := findingFor(res, "injection", name)
		if f.Rule != id || f.Line == 0 || f.CWE == "" || f.Fix == "" || f.Tier != "info" {
			t.Errorf("%s: want a finding of %s, got %+v", name, id, f)
		}
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Path, "vendor") {
			t.Errorf("vendor/ was read: %+v", f)
		}
	}
	out, _ := json.Marshal(res)
	for _, c := range code {
		for _, line := range strings.Split(c, "\n") {
			if len(line) > 12 && strings.Contains(string(out), line) {
				t.Errorf("the audit result contains code: %q", line)
			}
		}
	}
}

// Files the rules could not finish are summed up in one info finding with at most 10 paths.
func TestAppCodeAuditPartial(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	for i := range 11 {
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("open%02d.php", i)), []byte("<?php\n$a = 'never closed\n"), 0o644)
	}
	big := "<?php\n" + strings.Repeat("$a = 1;\n", auditMaxSize/8+1)
	os.WriteFile(filepath.Join(dir, "big.php"), []byte(big), 0o644)
	os.WriteFile(filepath.Join(dir, "ok.py"), []byte("print(1)\n"), 0o644)
	res := AppCodeAudit(context.Background(), []string{dir}, nil)
	var notes []CodeFinding
	for _, f := range res.Findings {
		if f.Kind == "injection" {
			notes = append(notes, f)
		}
	}
	if len(notes) != 1 {
		t.Fatalf("want one summary finding, got %+v", notes)
	}
	n := notes[0]
	if n.Severity != "info" || n.Tier != "info" || len(n.Files) != partialListMax || !strings.HasPrefix(n.Detail, "12 file(s)") ||
		!strings.Contains(n.Detail, "1 over the size limit") || !strings.Contains(n.Detail, "11 with a string or comment that never ends") {
		t.Errorf("summary: %+v", n)
	}
	for _, f := range n.Files {
		want := "unterminated"
		if strings.HasSuffix(f.Path, "big.php") {
			want = "size"
		}
		if strings.HasSuffix(f.Path, "ok.py") || f.Reason != want {
			t.Errorf("listed: %+v", f)
		}
	}
}

// A panic in the engine and the audit's time limit both leave the file in the summary.
func TestAppCodeAuditInjectionLimits(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	os.WriteFile(filepath.Join(dir, "a.php"), []byte("<?php\necho 1;\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "b.py"), []byte("print(1)\n"), 0o644)
	summary := func() CodeFinding {
		for _, f := range AppCodeAudit(context.Background(), []string{dir}, nil).Findings {
			if f.Kind == "injection" {
				return f
			}
		}
		return CodeFinding{}
	}
	scan := engineScan
	defer func() { engineScan = scan }()
	engineScan = func(e *engine.Engine, lang, p string, b []byte) ([]engine.Finding, error) {
		if lang == "php" {
			panic("boom")
		}
		return scan(e, lang, p, b)
	}
	if f := summary(); len(f.Files) != 1 || !strings.HasSuffix(f.Files[0].Path, "a.php") || f.Files[0].Reason != "panic" {
		t.Errorf("panic: summary %+v", f)
	}
	engineScan = scan
	max := injectionMaxTime
	defer func() { injectionMaxTime = max }()
	injectionMaxTime = 0
	if f := summary(); len(f.Files) != 2 || f.Files[0].Reason != "time" || f.Files[1].Reason != "time" {
		t.Errorf("time limit: summary %+v", f)
	}
}

// Every PHP extension the audit knows is scanned by the rules, and a NUL byte does
// not hide a file (the review of 888da12, items 4 and 6).
func TestAppCodeAuditExtensionsAndNUL(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	files := map[string]string{
		"a.phtml": "<?php\nsystem($_GET['a']);\n",
		"b.php5":  "<?php\nsystem($_GET['b']);\n",
		"c.inc":   "<?php\nsystem($_GET['c']);\n",
		"d.php":   "<?php\n\x00\nsystem($_GET['d']);\n",
	}
	for n, c := range files {
		os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644)
	}
	res := AppCodeAudit(context.Background(), []string{dir}, nil)
	for n := range files {
		if f := findingFor(res, "injection", n); f.Rule == "" {
			t.Errorf("%s: not scanned by the rules", n)
		}
	}
	if engine.LangOf("x.php5") != "php" || engine.LangOf("x.phtml") != "php" || engine.LangOf("x.inc") != "php" {
		t.Error("LangOf and the audit disagree on PHP extensions")
	}
}
