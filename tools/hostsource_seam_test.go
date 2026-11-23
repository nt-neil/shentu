package tools

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// S-181-1: SetHostSourceForTest is in the product binary (other packages'
// tests need it exported); no product code may use it. The name outside a
// _test.go file, called or as a value, fails here.
func TestSetHostSourceForTestOnlyInTests(t *testing.T) {
	filepath.WalkDir("..", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		for i, line := range strings.Split(string(b), "\n") {
			// The name itself, called or taken as a value (S-181r-1), but
			// for its definition and comments.
			code, _, _ := strings.Cut(line, "//")
			if strings.Contains(code, "SetHostSourceForTest") && !strings.HasPrefix(strings.TrimSpace(code), "func SetHostSourceForTest(") {
				t.Errorf("%s:%d calls SetHostSourceForTest outside a test", p, i+1)
			}
		}
		return nil
	})
}
