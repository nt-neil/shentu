package hostenv

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Only exec.go may start processes, and nothing in hostenv may build a
// shell command line.
func TestInvariantNoShellNoStrayExec(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, bad := range []string{`"-c"`, `"/c"`, `"-Command"`, `"sh"`, `"bash"`, `powershell.exe"`} {
			if name == "exec.go" && (bad == `"sh"` || bad == `"bash"`) {
				continue // the interpreter denylist names them
			}
			if strings.Contains(src, bad) {
				t.Errorf("%s contains %s", name, bad)
			}
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, b, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			if imp.Path.Value == `"os/exec"` && name != "exec.go" {
				t.Errorf("%s imports os/exec; only exec.go may", name)
			}
		}
	}
}
