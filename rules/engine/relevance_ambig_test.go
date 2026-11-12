package engine

import (
	"testing"
	"time"
)

// Names several files declare, calling one another: reading one file's call
// graph must not read another's that leads back to the first, half read (it
// recursed until the stack overflowed on a cvebench holdout release).
func TestRelevanceAmbiguousNamesInACycle(t *testing.T) {
	files := map[string]string{
		"main.php": "<?php\nf($_GET['x']);\n",
		"p1.php":   "<?php\nfunction f($x) { g($x); }\n",
		"p2.php":   "<?php\nfunction f($x) { g($x); }\n",
		"q1.php":   "<?php\nfunction g($x) { f($x); system($x); }\n",
		"q2.php":   "<?php\nfunction g($x) { f($x); }\n",
	}
	paths := []string{"main.php", "p1.php", "p2.php", "q1.php", "q2.php"}
	e := engineForTest(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		pr := e.NewProject(paths, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{MaxTime: time.Minute})
		for _, p := range paths {
			pr.ScanCalls(p, []byte(files[p]))
		}
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("following calls through names several files declare did not finish")
	}
}
