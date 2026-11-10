package engine

import (
	"errors"
	"reflect"
	"testing"
)

// What a result kept between audits depends on: the files its calls were
// followed into (Deps), every finding of the file (not only those no other
// file returned first), and whether it holds at all (timed: a callee that
// could not be read).
func TestProjectKeptResults(t *testing.T) {
	e := engineForTest(t)
	files := map[string]string{
		"a.php": "<?php\nrequire 'b.php';\nrun_cmd($_GET['x']);\n",
		"d.php": "<?php\nrequire 'b.php';\nrun_cmd($_GET['y']);\n",
		"b.php": "<?php\nfunction run_cmd($x) {\n\tsystem('ls ' . $x);\n}\n",
	}
	gone := ""
	read := func(p string) ([]byte, error) {
		if p == gone {
			return nil, errors.New("changed")
		}
		return []byte(files[p]), nil
	}
	pr := e.NewProject([]string{"a.php", "b.php", "d.php"}, read, ProjectOptions{})
	fa, timed, _ := pr.ScanCallsTimed("a.php", []byte(files["a.php"]))
	fd, _, _ := pr.ScanCallsTimed("d.php", []byte(files["d.php"]))
	if timed || len(fa) != 1 || !reflect.DeepEqual(fa, fd) {
		t.Errorf("a.php %v (timed %v), d.php %v: want the same b.php:3 for both", fa, timed, fd)
	}
	if !reflect.DeepEqual(pr.Deps("a.php"), []string{"b.php"}) || !reflect.DeepEqual(pr.Deps("d.php"), []string{"b.php"}) {
		t.Errorf("deps: a.php %v, d.php %v", pr.Deps("a.php"), pr.Deps("d.php"))
	}
	if pr.IndexDigest("php") == e.NewProject([]string{"a.php", "b.php"}, read, ProjectOptions{}).IndexDigest("php") {
		t.Error("the digest does not change with the files")
	}

	gone = "b.php"
	pr = e.NewProject([]string{"a.php", "b.php", "d.php"}, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{})
	pr.read = read
	if _, timed, _ := pr.ScanCallsTimed("a.php", []byte(files["a.php"])); timed || !pr.Unsteady() {
		t.Errorf("a callee that could not be read: timed %v, unsteady %v; want only unsteady", timed, pr.Unsteady())
	}
	// Asked again from another caller, after the first caller's answer was remembered.
	if _, _, _ = pr.ScanCallsTimed("d.php", []byte(files["d.php"])); !pr.Unsteady() {
		t.Error("the second caller of an unread callee is not unsteady")
	}
}

// ScanCallsPart leaves out the rules it is told were done, and reports the
// rules it followed to their end.
func TestProjectScanCallsPart(t *testing.T) {
	e := engineForTest(t)
	files := map[string]string{
		"a.php": "<?php\nrequire 'b.php';\nrun_cmd($_GET['x']);\n",
		"b.php": "<?php\nfunction run_cmd($x) {\n\tsystem('ls ' . $x);\n}\n",
	}
	read := func(p string) ([]byte, error) { return []byte(files[p]), nil }
	pr := e.NewProject([]string{"a.php", "b.php"}, read, ProjectOptions{})
	all, done, cut, timed, err := pr.ScanCallsPart("a.php", []byte(files["a.php"]), nil)
	if len(all) != 1 || len(done) < 2 || cut || timed || err != nil {
		t.Fatalf("whole: %v done %v cut %v timed %v err %v", all, done, cut, timed, err)
	}
	skip := map[string]bool{}
	for _, r := range done {
		if r != all[0].RuleID {
			skip[r] = true
		}
	}
	pr = e.NewProject([]string{"a.php", "b.php"}, read, ProjectOptions{})
	rest, done2, _, _, _ := pr.ScanCallsPart("a.php", []byte(files["a.php"]), skip)
	if !reflect.DeepEqual(rest, all) || !reflect.DeepEqual(done2, []string{all[0].RuleID}) {
		t.Errorf("the rest: %v done %v, want %v done [%s]", rest, done2, all, all[0].RuleID)
	}
}
