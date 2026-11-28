//go:build !windows

package tools

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A composer.json or composer.lock that is no regular file (a FIFO here) is
// not read, so the packages it may name are not known: the project's own
// find() is reported as before.
func TestAppCodeAuditReceiversComposerNotRegular(t *testing.T) {
	const rule = "php-nosqli-mongo-query"
	for _, name := range []string{"composer.json", "composer.lock"} {
		t.Run(name, func(t *testing.T) {
			dir, _ := filepath.EvalSymlinks(t.TempDir())
			for rel, body := range map[string]string{
				"handler.php": "<?php\nrequire 'svc.php';\nlookup($_GET['n']);\n",
				"svc.php":     "<?php\nfunction lookup($n) {\n  global $col;\n  return $col->find(['name' => $n]);\n}\n",
				"inc/db.php":  "<?php\nclass MyDb {\n  function find($q) {\n    return [];\n  }\n}\n",
			} {
				os.MkdirAll(filepath.Dir(filepath.Join(dir, rel)), 0o755)
				if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := syscall.Mkfifo(filepath.Join(dir, name), 0o644); err != nil {
				t.Skip("no FIFO here:", err)
			}
			res := AppCodeAudit(context.Background(), []string{dir}, nil)
			got := false
			for _, f := range res.Findings {
				got = got || f.Kind == "injection" && filepath.Base(f.Path) == "svc.php" && f.Rule == rule
			}
			if !got {
				t.Errorf("%s at svc.php not reported with a %s that is a FIFO", rule, name)
			}
		})
	}
}
