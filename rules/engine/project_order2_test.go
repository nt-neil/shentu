package engine

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"
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
