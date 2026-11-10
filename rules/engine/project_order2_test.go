package engine

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// What following one file's calls finds, and whether a cap cut it short, does
// not depend on the files scanned before it in the project (the summaries
// they left behind used to make the work cap fall later): an audit that takes
// the files a part at a time, in another order, gets every file's result as
// one audit of all of them does.
func TestProjectResultPerFileWhateverTheOrder(t *testing.T) {
	e := engineForTest(t)
	e.Limits.MaxCallWork = 900 // low enough that a callee's summary is a good part of it
	files := map[string]string{
		"lib.php": "<?php\nfunction clean($v) {\n\t$v = trim($v);\n\t$v = str_replace('a', 'b', $v);\n\t$v = strtolower($v);\n\treturn $v;\n}\n" +
			"function run_it($x) {\n\t$y = clean($x);\n\t$z = clean($y);\n\tsystem('ls ' . $z);\n}\n",
		"a.php": "<?php\nrequire 'lib.php';\nrun_it($_GET['a']);\n",
		"b.php": "<?php\nrequire 'lib.php';\nfunction viaB($q) {\n\trun_it(clean($q));\n}\nviaB($_GET['b']);\n",
		"c.php": "<?php\nrequire 'lib.php';\n$k = clean(clean($_POST['c']));\nrun_it($k);\n",
	}
	paths := []string{"a.php", "b.php", "c.php", "lib.php"}
	read := func(p string) ([]byte, error) { return []byte(files[p]), nil }
	scanAll := func(order []string) map[string]string {
		pr := e.NewProject(paths, read, ProjectOptions{})
		out := map[string]string{}
		for _, p := range order {
			fs, timed, err := pr.ScanCallsTimed(p, []byte(files[p]))
			out[p] = fmt.Sprint(fs, timed, err)
		}
		return out
	}
	want := map[string]string{}
	for _, p := range paths {
		want[p] = scanAll([]string{p})[p] // each file in a project of its own
	}
	orders := [][]string{paths, {"lib.php", "c.php", "b.php", "a.php"}, {"b.php", "a.php", "lib.php", "c.php"}}
	rnd := rand.New(rand.NewPCG(1, 2))
	for range 5 {
		o := slices.Clone(paths)
		rnd.Shuffle(len(o), func(i, j int) { o[i], o[j] = o[j], o[i] })
		orders = append(orders, o)
	}
	for _, order := range orders {
		if got := scanAll(order); !reflect.DeepEqual(got, want) {
			t.Errorf("order %v:\n got %v\nwant %v", order, got, want)
		}
	}
}

// The same with calls cycling across files, functions declared in several
// files, and files reaching the work cap (the project of
// TestProjectDeterministic), scanned forward, reversed and shuffled.
func TestProjectCyclesWhateverTheOrder(t *testing.T) {
	files := map[string]string{}
	var paths []string
	const n = 12
	for i := range n {
		var b strings.Builder
		b.WriteString("<?php\n")
		for j := range 4 {
			next := fmt.Sprintf("f%d_%d", (i+1)%n, (j+3)%4)
			back := fmt.Sprintf("f%d_%d", (i+n-1)%n, j)
			fmt.Fprintf(&b, "function f%d_%d($v, $w) {\n  if ($v == 'a') { return %s($w, $v); }\n  if (!in_array($w, array('x', 'y'), true)) { %s($v, $w); }\n"+
				"  system('ls ' . $v);\n  return trim($w);\n}\n", i, j, next, back)
		}
		if i%4 == 0 {
			b.WriteString("function dup($v) { system('id ' . $v); }\n")
			fmt.Fprintf(&b, "f%d_0($_GET['a'], dup($_POST['b']));\n", i)
		}
		p := fmt.Sprintf("m%02d.php", i)
		files[p] = b.String()
		paths = append(paths, p)
	}
	read := func(p string) ([]byte, error) { return []byte(files[p]), nil }
	for _, c := range []struct{ work, tokens int }{{0, 0}, {20_000, 0}, {60_000, 0}, {0, 200}, {20_000, 200}} {
		work := c.work
		scan := func(order []string) map[string]string {
			e := engineForTest(t)
			e.Limits.MaxTime = time.Minute
			e.Limits.MaxCallWork = work
			// tokens 200: files are let go of all the time (LRU), cycles being settled included
			pr := e.NewProject(paths, read, ProjectOptions{MaxTime: time.Hour, MaxTokens: c.tokens})
			out := map[string]string{}
			for _, p := range order {
				fs, timed, err := pr.ScanCallsTimed(p, []byte(files[p]))
				out[p] = fmt.Sprint(fs, timed, err)
			}
			return out
		}
		want := scan(paths)
		rev := slices.Clone(paths)
		slices.Reverse(rev)
		orders := [][]string{rev}
		rnd := rand.New(rand.NewPCG(3, 4))
		for range 3 {
			o := slices.Clone(paths)
			rnd.Shuffle(len(o), func(i, j int) { o[i], o[j] = o[j], o[i] })
			orders = append(orders, o)
		}
		for _, o := range orders {
			if got := scan(o); !reflect.DeepEqual(got, want) {
				for _, p := range paths {
					if got[p] != want[p] {
						t.Errorf("work %d, tokens %d, order %v, %s:\n got %s\nwant %s", work, c.tokens, o, p, got[p], want[p])
						break
					}
				}
			}
		}
	}
}
