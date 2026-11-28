package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/rules"
	"github.com/nt-neil/shentu/rules/engine"
)

// cvebench gives the project what app_code_audit gives it for the rules'
// receivers: composer.lock, the package names under vendor/ (not read), and
// whether a file was left out (NamesIncomplete), so a release's own find()
// counts as its own only where the product would let it.
func TestScanReceivers(t *testing.T) {
	rs, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(rs)
	if err != nil {
		t.Fatal(err)
	}
	base := map[string]string{
		"handler.php": "<?php\nrequire 'svc.php';\nlookup($_GET['n']);\n",
		"svc.php":     "<?php\nfunction lookup($n) {\n  global $col;\n  return $col->find(['name' => $n]);\n}\n",
		"inc/db.php":  "<?php\nclass MyDb {\n  function find($q) {\n    return [];\n  }\n}\n",
	}
	for _, c := range []struct {
		name       string
		extra      map[string]string
		reported   bool
		incomplete bool
	}{
		{"nothing names MongoDB", nil, false, false},
		{"vendor/mongodb/mongodb", map[string]string{"vendor/mongodb/mongodb/src/Client.php": "<?php\n"}, true, false},
		{"composer.lock lists it", map[string]string{"composer.lock": `{"packages": [{"name": "mongodb/mongodb"}]}`}, true, false},
		{"node_modules/ is skipped", map[string]string{"node_modules/x/i.js": "module.exports = 1\n"}, true, true},
		{"a file too deep for app_code_audit", map[string]string{"a/b/c/d/e/f/g/h/i/x.php": "<?php\n"}, true, true},
		{"a script over the size limit", map[string]string{"js/app.min.js": "var a=1;" + strings.Repeat("a=a+1;", maxScanFile/6+1)}, false, false},
		{"a PHP file over the size limit", map[string]string{"lib/big.php": "<?php\n" + strings.Repeat("$a = 1;\n", maxScanFile/8+1)}, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			for rel, body := range base {
				os.MkdirAll(filepath.Dir(filepath.Join(dir, rel)), 0o755)
				os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o644)
			}
			for rel, body := range c.extra {
				os.MkdirAll(filepath.Dir(filepath.Join(dir, rel)), 0o755)
				os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o644)
			}
			r := scan(eng, dir, pathProduct)
			got := false
			for _, f := range r.Findings {
				got = got || f.Path == "svc.php" && f.RuleID == "php-nosqli-mongo-query"
			}
			if got != c.reported || r.NamesIncomplete != c.incomplete {
				t.Errorf("reported %v, incomplete %v; want %v, %v", got, r.NamesIncomplete, c.reported, c.incomplete)
			}
		})
	}
}
