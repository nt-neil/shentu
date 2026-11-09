package engine

// Differential run for PR #20 review: scans a corpus (R20_CORPUS) and writes the
// findings of the five original classes to R20_OUT, one per line, so the base
// and head trees can be compared with diff. Skipped unless R20_CORPUS is set.

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/rules"
)

func TestR20Diff(t *testing.T) {
	root, out := os.Getenv("R20_CORPUS"), os.Getenv("R20_OUT")
	if root == "" || out == "" {
		t.Skip("R20_CORPUS / R20_OUT not set")
	}
	rs, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(rs)
	if err != nil {
		t.Fatal(err)
	}
	old := []string{"-sqli-", "-cmdi-", "-path-traversal-", "-deserialization-", "-code-eval-"}
	langOf := map[string]string{".php": "php", ".py": "python", ".js": "js"}
	var lines []string
	var slow []string
	n := 0
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		lang := langOf[filepath.Ext(p)]
		if lang == "" {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 256<<10 {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		n++
		start := time.Now()
		fsd, serr := e.Scan(lang, p, src)
		if el := time.Since(start); el > 2*time.Second {
			slow = append(slow, fmt.Sprintf("%s %v", p, el))
		}
		for _, f := range fsd {
			for _, o := range old {
				if strings.Contains(f.RuleID, o) {
					lines = append(lines, fmt.Sprintf("%s:%d:%s", strings.TrimPrefix(p, root), f.Line, f.RuleID))
				}
			}
		}
		if serr != nil {
			lines = append(lines, fmt.Sprintf("%s:0:ERR %v", strings.TrimPrefix(p, root), serr))
		}
		return nil
	})
	sort.Strings(lines)
	os.WriteFile(out, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	t.Logf("files %d, lines %d, slow %d: %v", n, len(lines), len(slow), slow)
}
