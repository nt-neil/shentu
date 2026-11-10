package engine

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// The same project scanned twice gives the same findings and the same errors,
// file for file: with calls that cycle across files, functions declared twice,
// and files that reach the work cap for following calls (the review of 2ee6841,
// where one WordPress finding came and went with the machine's load).
func TestProjectDeterministic(t *testing.T) {
	files := map[string]string{}
	var paths []string
	const n = 40
	for i := range n {
		var b strings.Builder
		b.WriteString("<?php\n")
		for j := range 8 {
			next := fmt.Sprintf("f%d_%d", (i+1)%n, (j+3)%8)
			back := fmt.Sprintf("f%d_%d", (i+n-1)%n, j)
			fmt.Fprintf(&b, "function f%d_%d($v, $w) {\n  if ($v == 'a') { return %s($w, $v); }\n  if (!in_array($w, array('x', 'y'), true)) { %s($v, $w); }\n"+
				"  system('ls ' . $v);\n  return trim($w);\n}\n", i, j, next, back)
		}
		if i%5 == 0 {
			b.WriteString("function dup($v) { system('id ' . $v); }\n") // declared in several files
			fmt.Fprintf(&b, "f%d_0($_GET['a'], dup($_POST['b']));\n", i)
		}
		p := fmt.Sprintf("m%02d.php", i)
		files[p] = b.String()
		paths = append(paths, p)
	}
	run := func(work int) []string {
		e := engineForTest(t)
		e.Limits.MaxTime = time.Minute // the clock out of the way: only the work cap may cut
		e.Limits.MaxCallWork = work
		pr := e.NewProject(paths, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{MaxTime: time.Hour})
		var out []string
		for _, p := range paths {
			fs, err := pr.Scan(p, []byte(files[p]))
			for _, f := range fs {
				out = append(out, fmt.Sprintf("%s:%d %s", f.Path, f.Line, f.RuleID))
			}
			if err != nil {
				out = append(out, p+" "+err.Error())
			}
		}
		slices.Sort(out)
		return out
	}
	for _, work := range []int{0, 20_000} { // the default cap, and one most files reach
		a, b := run(work), run(work)
		if !slices.Equal(a, b) {
			t.Errorf("work cap %d: two runs differ\n%v\n%v", work, a, b)
		}
		if len(a) == 0 {
			t.Errorf("work cap %d: nothing found", work)
		}
	}
}
