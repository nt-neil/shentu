package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/rules/engine"
)

// keptAudit runs the audit with a state directory, recording which files each
// pass scanned (not taken from the kept results).
type keptAudit struct {
	t          *testing.T
	dir, state string
	own, calls []string
	cutAfter   int        // > 0: the clock runs out after this many files' calls in one audit
	cutAll     bool       // the clock runs out during every file's calls
	oneRule    bool       // the clock runs out in each file after one more rule
	skips      [][]string // the rules each scan was told to leave out
}

func newKeptAudit(t *testing.T, files map[string]string) *keptAudit {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	for n, c := range files {
		os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644)
	}
	k := &keptAudit{t: t, dir: dir, state: filepath.Join(t.TempDir(), "state")}
	idx, scan, calls := codeIndexFile, engineScan, projectScan
	t.Cleanup(func() { codeIndexFile, engineScan, projectScan = idx, scan, calls })
	codeIndexFile = func() string { return filepath.Join(k.state, "codeindex.json") }
	engineScan = func(e *engine.Engine, lang, p string, b []byte) ([]engine.Finding, bool, error) {
		k.own = append(k.own, filepath.Base(p))
		return scan(e, lang, p, b)
	}
	projectScan = func(pr *engine.Project, p string, b []byte, skip map[string]bool) ([]engine.Finding, []string, bool, bool, error) {
		k.calls = append(k.calls, filepath.Base(p))
		var sk []string
		for r := range skip {
			sk = append(sk, r)
		}
		sort.Strings(sk)
		k.skips = append(k.skips, sk)
		f, done, cut, timed, err := calls(pr, p, b, skip)
		if k.oneRule && len(done) > 1 {
			keep := done[0] // as if the clock ran out right after this rule
			var kept []engine.Finding
			for _, x := range f {
				if x.RuleID == keep {
					kept = append(kept, x)
				}
			}
			return kept, done[:1], cut, true, err
		}
		if k.cutAll || k.cutAfter > 0 && len(k.calls) > k.cutAfter {
			// As if the clock had run out during this file, before any rule was done.
			return nil, nil, false, true, err
		}
		return f, done, cut, timed, err
	}
	return k
}

// run audits once and returns the injection findings (base:line rule) and the
// summary of calls across files ("" when every file's calls were followed).
func (k *keptAudit) run() (found []string, summary string) {
	k.own, k.calls, k.skips = nil, nil, nil
	for _, f := range AppCodeAudit(context.Background(), []string{k.dir}, nil).Findings {
		switch {
		case f.Kind != "injection":
		case f.Rule != "":
			found = append(found, fmt.Sprintf("%s:%d %s", filepath.Base(f.Path), f.Line, f.Rule))
		case strings.Contains(f.Detail, "calls across files"):
			summary = f.Detail
		}
	}
	sort.Strings(found)
	sort.Strings(k.own)
	sort.Strings(k.calls)
	return found, summary
}

var keptFiles = map[string]string{
	"a.php": "<?php\nrequire 'b.php';\nrun_cmd($_GET['x']);\n",
	"b.php": "<?php\nfunction run_cmd($x) {\n\tsystem('ls ' . $x);\n}\n",
	"c.php": "<?php\nfunction other($y) {\n\techo 1;\n}\n",
}

// An audit keeps its results (mode 0600, no code); the next one takes them for
// unchanged files, and after a change scans that file again and the files
// whose calls reached it, nothing else.
func TestAppCodeAuditKeepsResults(t *testing.T) {
	k := newKeptAudit(t, keptFiles)
	first, sum := k.run()
	if len(first) == 0 || !strings.HasPrefix(first[0], "b.php:3 ") || sum != "" {
		t.Fatalf("first audit: %v %q", first, sum)
	}
	if !reflect.DeepEqual(k.calls, []string{"a.php", "b.php", "c.php"}) {
		t.Errorf("first audit followed the calls of %v", k.calls)
	}
	states, _ := filepath.Glob(filepath.Join(k.state, "codecalls-*.json"))
	if len(states) != 1 {
		t.Fatalf("state files: %v", states)
	}
	info, _ := os.Stat(states[0])
	b, _ := os.ReadFile(states[0])
	if info.Mode().Perm() != 0o600 || strings.Contains(string(b), "system(") || strings.Contains(string(b), "$_GET") {
		t.Errorf("state file: mode %v, %s", info.Mode().Perm(), b)
	}

	again, sum := k.run()
	if !reflect.DeepEqual(again, first) || sum != "" || len(k.own) != 0 || len(k.calls) != 0 {
		t.Errorf("unchanged: %v %q, scanned %v %v", again, sum, k.own, k.calls)
	}

	// The callee changes: it and its caller are scanned again, c.php is not.
	os.WriteFile(filepath.Join(k.dir, "b.php"), []byte("<?php\n// moved\nfunction run_cmd($x) {\n\tsystem('ls ' . $x);\n}\n"), 0o644)
	moved, _ := k.run()
	if len(moved) == 0 || !strings.HasPrefix(moved[0], "b.php:4 ") || slicesHasPrefix(moved, "b.php:3 ") {
		t.Errorf("after the change: %v", moved)
	}
	if !reflect.DeepEqual(k.own, []string{"b.php"}) || !reflect.DeepEqual(k.calls, []string{"a.php", "b.php"}) {
		t.Errorf("after the change scanned %v and followed %v", k.own, k.calls)
	}

	// A new function changes the names PHP files declare: calls may resolve
	// elsewhere, so every PHP file's calls are followed again.
	os.WriteFile(filepath.Join(k.dir, "c.php"), []byte("<?php\nfunction other($y) {\n\techo 1;\n}\nfunction more() {}\n"), 0o644)
	k.run()
	if !reflect.DeepEqual(k.own, []string{"c.php"}) || !reflect.DeepEqual(k.calls, []string{"a.php", "b.php", "c.php"}) {
		t.Errorf("after a new function scanned %v and followed %v", k.own, k.calls)
	}
}

// When the clock runs out, the next audit goes on from the files not covered
// yet, and once all are covered the result is that of one audit with time
// for all of them.
func TestAppCodeAuditResumes(t *testing.T) {
	whole, _ := newKeptAudit(t, keptFiles).run()
	k := newKeptAudit(t, keptFiles)
	k.cutAfter = 1
	var sums []string
	var followed [][]string
	var got []string
	for range 5 {
		f, sum := k.run()
		got = f
		followed = append(followed, k.calls)
		if sum == "" {
			break
		}
		sums = append(sums, sum)
	}
	want := [][]string{{"a.php", "b.php"}, {"b.php", "c.php"}, {"c.php"}}
	if !reflect.DeepEqual(followed, want) {
		t.Errorf("followed %v, want %v", followed, want)
	}
	if len(sums) != 2 || !strings.Contains(sums[0], "covered for 1 of 3 file(s) (33.3%) so far, 1 of them in this audit") ||
		!strings.Contains(sums[1], "covered for 2 of 3 file(s) (66.7%) so far, 1 of them in this audit") {
		t.Errorf("summaries: %q", sums)
	}
	if !reflect.DeepEqual(got, whole) {
		t.Errorf("covered over several audits %v, in one %v", got, whole)
	}
}

// A result that a change made stale is dropped at once: when that audit has
// no time to scan the file again, the next one still does.
func TestAppCodeAuditStaleNotKept(t *testing.T) {
	k := newKeptAudit(t, keptFiles)
	k.run()
	os.WriteFile(filepath.Join(k.dir, "b.php"), []byte("<?php\n// moved\nfunction run_cmd($x) {\n\tsystem('ls ' . $x);\n}\n"), 0o644)
	k.cutAll = true
	k.run()
	k.cutAll = false
	found, _ := k.run()
	if !reflect.DeepEqual(k.calls, []string{"a.php", "b.php"}) || len(found) == 0 || !strings.HasPrefix(found[0], "b.php:4 ") {
		t.Errorf("after an audit cut short: followed %v, found %v", k.calls, found)
	}
}

// Every caller of a changed file is scanned again, also one whose answer about
// it came from what the project remembered from another caller.
func TestAppCodeAuditEveryCallerAgain(t *testing.T) {
	k := newKeptAudit(t, map[string]string{
		"a.php": "<?php\nrequire 'b.php';\nquiet($_GET['x']);\n",
		"b.php": "<?php\nfunction quiet($x) {\n\techo 1;\n}\n",
		"d.php": "<?php\nrequire 'b.php';\nquiet($_GET['y']);\n",
	})
	if found, _ := k.run(); len(found) != 0 {
		t.Fatalf("before: %v", found)
	}
	os.WriteFile(filepath.Join(k.dir, "b.php"), []byte("<?php\nfunction quiet($x) {\n\tsystem('ls ' . $x);\n}\n"), 0o644)
	found, _ := k.run()
	if !reflect.DeepEqual(k.calls, []string{"a.php", "b.php", "d.php"}) || len(found) == 0 {
		t.Errorf("after the change: followed %v, found %v", k.calls, found)
	}
}

// A file the clock cuts short in every audit still gets done, a rule at a
// time: each audit goes on from the rules the last ones finished.
func TestAppCodeAuditResumesWithinAFile(t *testing.T) {
	whole, _ := newKeptAudit(t, keptFiles).run()
	k := newKeptAudit(t, keptFiles)
	k.oneRule = true
	var got []string
	grew := true
	for i := 0; i < 200 && grew; i++ {
		got, _ = k.run()
		grew = len(k.calls) > 0
		if i > 0 && grew && len(k.skips[0]) == 0 {
			t.Fatalf("audit %d started the file over: %v", i+1, k.skips)
		}
	}
	if grew {
		t.Fatal("the file was never done")
	}
	if !reflect.DeepEqual(got, whole) {
		t.Errorf("done a rule at a time %v, in one audit %v", got, whole)
	}
}

func slicesHasPrefix(s []string, prefix string) bool {
	for _, x := range s {
		if strings.HasPrefix(x, prefix) {
			return true
		}
	}
	return false
}
