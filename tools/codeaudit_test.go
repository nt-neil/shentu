package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		pub + "/.env":                     "APP_KEY=x\n",
		pub + "/.git/HEAD":                "ref: refs/heads/main\n",
		pub + "/dump.sql":                 "INSERT INTO users VALUES (1);\n",
		pub + "/site-backup.zip":          "PK",
		pub + "/info.php":                 "<?php\nphpinfo();\n",
		pub + "/uploads/cat.php":          "<?php echo 1;\n",
		pub + "/shell.php":                "<?php\n\n@eval($_POST['x']);\n",
		app + "/settings.py":              "SECRET=1\nDEBUG = True\n",
		app + "/.env":                     "APP_ENV=production\nAPP_DEBUG=true\n",
		app + "/run.py":                   "from flask import Flask\napp = Flask(__name__)\napp.run(host='0.0.0.0', debug=True)\n",
		app + "/config.js":                "module.exports = {\n  key: '" + awsKey + "',\n}\n",
		app + "/db.py":                    "URL = 'postgres://shop:" + dbPass + "@db/shop'\n",
		pub + "/wp-load.php":              "<?php\n",
		pub + "/wp-includes/version.php":  "<?php\n$wp_version = '6.8.11';\n",
		pub + "/wp-content/upgrade/x.php": "<?php echo 1;\n",
		// should not be found
		dir + "/site/.env":                         "APP_DEBUG=false\n",
		pub + "/.env.example":                      "APP_KEY=\n",
		app + "/other/settings.py":                 "DEBUG = False\n",
		app + "/dev.py":                            "# app.run(debug=True)\n",
		app + "/notes.md":                          "remember phpinfo() and " + awsKey + "\n",
		pub + "/index.php":                         "<?php echo htmlspecialchars($_GET['q']);\n",
		dir + "/site/blog/wp-load.php":             "<?php\n",
		dir + "/site/blog/wp-includes/version.php": "<?php\n$wp_version = '6.8.12';\n",
		dir + "/site/blog/wp-content/plugins/seo/wp-includes/version.php": "<?php\n$wp_version = '1.0';\n",
		dir + "/site/blog/wp-content/plugins/seo/version.php":             "<?php\n$wp_version = '4.0';\n",
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
		"upload_script public/uploads/cat.php": "critical", "webshell public/shell.php": "critical",
		"debug app/settings.py": "warning", "debug app/.env": "warning", "debug app/run.py": "critical",
		"secret app/config.js": "warning", "secret app/db.py": "warning",
		"outdated public": "critical", "upload_script public/wp-content/upgrade/x.php": "critical",
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

func TestWordpressCore(t *testing.T) {
	site := t.TempDir()
	os.WriteFile(filepath.Join(site, "wp-load.php"), []byte("<?php\n"), 0o644)
	cases := map[string]bool{ // version → reported
		"7.1.3": true, "7.1.4": false, "7.1": true, "7.2": false, "6.8.11": true, "6.8.12": false,
		"4.7.38": true, "4.7.39": false, "4.6.1": true, "3.9": true, "8.0": false,
	}
	for v, want := range cases {
		var got []CodeFinding
		wordpressCore(filepath.Join(site, "wp-includes/version.php"), []byte("<?php\n$wp_version = '"+v+"';\n"), func(f CodeFinding) { got = append(got, f) })
		if (len(got) > 0) != want {
			t.Errorf("%s: got %+v, want reported=%v", v, got, want)
		}
		if len(got) > 0 && got[0].Path != site {
			t.Errorf("%s: path %s", v, got[0].Path)
		}
	}
}
