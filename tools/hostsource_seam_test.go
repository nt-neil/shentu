package tools

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// S-181-1: SetHostSourceForTest is in the product binary (other packages'
// tests need it exported); no product code may call it. A call outside a
// _test.go file fails here.
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
			if strings.Contains(line, "SetHostSourceForTest(") && !strings.HasPrefix(strings.TrimSpace(line), "func SetHostSourceForTest(") && !strings.HasPrefix(strings.TrimSpace(line), "//") {
				t.Errorf("%s:%d calls SetHostSourceForTest outside a test", p, i+1)
			}
		}
		return nil
	})
}
