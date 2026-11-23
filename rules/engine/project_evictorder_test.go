package engine

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// evictChain is a project whose entry file calls into a chain of functions
// spread over many files, none of which matters to any rule: working out
// whether the call matters walks the whole chain and finds nothing. With a
// token cap that holds only a few of the files, the walk lets go of the files
// it read first, and reads them again when it writes down what it found.
func evictChain(n int) (map[string]string, []string) {
	files := map[string]string{}
	var paths []string
	for i := range n {
		next := "return $v;"
		if i+1 < n {
			next = fmt.Sprintf("return g%02d($v . 'x');", i+1)
		}
		p := fmt.Sprintf("c%02d.php", i)
		files[p] = fmt.Sprintf("<?php\nfunction g%02d($v) {\n\t$v = trim($v);\n\t%s\n}\n", i, next)
		paths = append(paths, p)
	}
	files["a.php"] = "<?php\n$q = g00($_GET['a']);\nsystem('ls ' . escapeshellarg($q));\n"
	paths = append(paths, "a.php")
	return files, paths
}

// The files the project holds after a scan, and in which order it will let
// go of them, are the same on every run of the same scan: the walk asks for
// the files it visited in the order it reached them, not in a map's order.
// Which files are held decides which worked-out results are dropped and so
// what the next scan pays for them, which decides where a work cap falls.
func TestProjectEvictionOrderFixed(t *testing.T) {
	files, paths := evictChain(12)
	read := func(p string) ([]byte, error) { return []byte(files[p]), nil }
	run := func() []string {
		e := engineForTest(t)
		e.Limits.MaxTime = time.Minute
		pr := e.NewProject(paths, read, ProjectOptions{MaxTime: time.Hour, MaxTokens: 120})
		if _, _, err := pr.ScanCallsTimed("a.php", []byte(files["a.php"])); err != nil && !strings.Contains(err.Error(), "cut") {
			t.Fatal(err)
		}
		return slices.Clone(pr.lru)
	}
	want := run()
	if len(want) == 0 || len(want) >= len(paths) {
		t.Fatalf("the cap must let go of some files and keep some: held %v of %d", want, len(paths))
	}
	for i := range 30 {
		if got := run(); !slices.Equal(got, want) {
			t.Fatalf("run %d: held %v, first run %v", i+2, got, want)
		}
	}
}
