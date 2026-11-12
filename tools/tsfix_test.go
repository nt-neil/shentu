package tools

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// B5 (v0.2.5 review): TypeScript files index as JavaScript, so a change in the
// names JavaScript declares drops their results across files too. A new
// module that an unchanged .ts file imports is followed as it is for .js.
func TestAppCodeAuditDigestCoversTypeScript(t *testing.T) {
	route := "import { run } from './db';\napp.get('/x', (req, res) => { run(req.query.c); });\n"
	db := "const { exec } = require('child_process');\nexport function run(c) {\n  exec('ls ' + c);\n}\n"
	results := map[string][]string{}
	for _, ext := range []string{".js", ".ts", ".tsx", ".mts", ".jsx"} {
		k := newKeptAudit(t, map[string]string{"a" + ext: route})
		before, _ := k.run()
		os.WriteFile(filepath.Join(k.dir, "db"+ext), []byte(db), 0o644)
		after, _ := k.run()
		if len(before) != 0 {
			t.Errorf("%s: found before db%s was added: %v", ext, ext, before)
		}
		var norm []string
		for _, f := range after {
			norm = append(norm, strings.Replace(f, ext+":", ".X:", 1))
		}
		results[ext] = norm
	}
	if len(results[".js"]) == 0 {
		t.Fatalf("js: the new module's sink is not reported: %v", results)
	}
	for ext, got := range results {
		if !reflect.DeepEqual(got, results[".js"]) {
			t.Errorf("%s: %v, want %v as for .js", ext, got, results[".js"])
		}
	}
}
