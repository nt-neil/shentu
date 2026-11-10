package engine

import "testing"

// A cycle across files is found whatever order the files are indexed and
// scanned in (the order once decided whether a relevance memo said no).
func TestProjectCycleOrder(t *testing.T) {
	e := engineForTest(t)
	files := map[string]string{
		"a.php": "<?php\nfunction fa($v) { fb($v); }\nfa($_GET['x']);\n",
		"b.php": "<?php\nfunction fb($v) { if ($v) { fa($v); } system('ls ' . $v); }\n",
	}
	for _, order := range [][]string{{"a.php", "b.php"}, {"b.php", "a.php"}} {
		for _, idx := range [][]string{{"a.php", "b.php"}, {"b.php", "a.php"}} {
			pr := e.NewProject(idx, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{})
			var all []Finding
			for _, p := range order {
				fs, _ := pr.Scan(p, []byte(files[p]))
				all = append(all, fs...)
			}
			if len(all) != 1 || all[0].Path != "b.php" || all[0].Line != 2 {
				t.Errorf("index %v, scan %v: %v, want b.php:2", idx, order, all)
			}
		}
	}
}
