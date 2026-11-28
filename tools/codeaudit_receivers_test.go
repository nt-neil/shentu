package tools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// app_code_audit gives the project what the rules' receivers need to say a
// method sink is the project's own (N-284-2): composer.lock, the package
// names under vendor/, which it does not read, and whether it left a file of
// a rule language out. $col->find() on the project's own MyDb::find() is no
// MongoDB query only when nothing the audit skipped or could not read may
// name MongoDB.
func TestAppCodeAuditReceivers(t *testing.T) {
	const rule = "php-nosqli-mongo-query"
	base := map[string]string{
		"handler.php": "<?php\nrequire 'svc.php';\nlookup($_GET['n']);\n",
		"svc.php":     "<?php\nfunction lookup($n) {\n  global $col;\n  return $col->find(['name' => $n]);\n}\n",
		"inc/db.php":  "<?php\nclass MyDb {\n  function find($q) {\n    return [];\n  }\n}\n",
	}
	mongo := "<?php\nuse MongoDB\\Client;\n$c = new Client();\n"
	deep := strings.Repeat("d/", 10)
	for _, c := range []struct {
		name  string
		extra map[string]string
		mode  map[string]os.FileMode // files written with this mode
		want  bool
	}{
		{"nothing names MongoDB", nil, nil, false},
		{"another file names it", map[string]string{"lib/m.php": mongo}, nil, true},
		{"R3 only a file over the size limit names it", map[string]string{"lib/big.php": mongo + strings.Repeat("$x = 1;\n", auditMaxSize/8+1)}, nil, true},
		{"R4 only a file too deep names it", map[string]string{deep + "m.php": mongo}, nil, true},
		{"R5 only vendor/ holds it", map[string]string{"vendor/mongodb/mongodb/src/Client.php": "<?php\nnamespace MongoDB;\nclass Client {}\n"}, nil, true},
		{"vendor/ of other packages only", map[string]string{"vendor/guzzlehttp/guzzle/src/Client.php": "<?php\nclass Client {}\n"}, nil, false},
		{"R6 only composer.lock lists it", map[string]string{"composer.lock": `{"packages": [{"name": "mongodb/mongodb"}]}`}, nil, true},
		{"R10 a file that names it cannot be read", map[string]string{"lib/m.php": mongo}, map[string]os.FileMode{"lib/m.php": 0}, true},
		{"a folder the audit skips", map[string]string{"node_modules/x/index.js": "module.exports = 1\n"}, nil, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir, _ := filepath.EvalSymlinks(t.TempDir())
			write := func(rel, body string) {
				p := filepath.Join(dir, rel)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				mode := os.FileMode(0o644)
				if m, ok := c.mode[rel]; ok {
					mode = m
				}
				if err := os.WriteFile(p, []byte(body), mode); err != nil {
					t.Fatal(err)
				}
				os.Chmod(p, mode)
			}
			for rel, body := range base {
				write(rel, body)
			}
			for rel, body := range c.extra {
				write(rel, body)
			}
			res := AppCodeAudit(context.Background(), []string{dir}, nil)
			got := false
			var all []string
			for _, f := range res.Findings {
				if f.Kind == "injection" && f.Rule != "" {
					all = append(all, filepath.Base(f.Path)+" "+f.Rule)
					got = got || filepath.Base(f.Path) == "svc.php" && f.Rule == rule
				}
			}
			if got != c.want {
				t.Errorf("%s at svc.php: %v, want %v; all: %v", rule, got, c.want, all)
			}
		})
	}
}
