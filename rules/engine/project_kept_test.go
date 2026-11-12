package engine

import (
	"errors"
	"reflect"
	"testing"
	"time"
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
	whole, err := pr.ScanCallsPart("a.php", []byte(files["a.php"]), nil)
	all, done := whole.Found, whole.Done
	if len(all) != 1 || len(done) < 2 || whole.Cut || whole.Timed || whole.At != "" || err != nil {
		t.Fatalf("whole: %+v err %v", whole, err)
	}
	skip := map[string]bool{}
	for _, r := range done {
		if r != all[0].RuleID {
			skip[r] = true
		}
	}
	pr = e.NewProject([]string{"a.php", "b.php"}, read, ProjectOptions{})
	part, _ := pr.ScanCallsPart("a.php", []byte(files["a.php"]), skip)
	rest, done2 := part.Found, part.Done
	if !reflect.DeepEqual(rest, all) || !reflect.DeepEqual(done2, []string{all[0].RuleID}) {
		t.Errorf("the rest: %v done %v, want %v done [%s]", rest, done2, all, all[0].RuleID)
	}
}

// A rule run after the project's clock ran out followed no call across files
// (resolution stops silently once the project stops): it is not done, and
// its findings are not the rule's. Only rules finished before are, so that
// the next audit runs the rest again (an audit took a rule's result without
// its cross-file flows as complete, and the findings never came back).
func TestProjectScanCallsPartAfterTheClock(t *testing.T) {
	e := engineForTest(t)
	files := map[string]string{
		"a.php": "<?php\nrequire 'b.php';\nrun_cmd($_GET['x']);\n",
		"b.php": "<?php\nfunction run_cmd($x) {\n\tsystem('ls ' . $x);\n}\n",
	}
	read := func(p string) ([]byte, error) { return []byte(files[p]), nil }
	pr := e.NewProject([]string{"a.php", "b.php"}, read, ProjectOptions{})
	// The project's clock (or heap) stopped calls crossing files during the
	// scan; the scan's own clock, read every few thousand steps, has not yet.
	pr.stop("following calls across files ran out of time")
	pr.byMachine = true
	part, _ := pr.ScanCallsPart("a.php", []byte(files["a.php"]), nil)
	if !part.Timed || len(part.Done) != 0 || len(part.Found) != 0 {
		t.Errorf("after the project stopped: %+v, want timed with no rule done", part)
	}
}

// A scan over the file's own time limit says so (FileTime), apart from one
// the project's clock cut short: the audit goes on with other files only in
// the first case.
func TestScanCallsPartFileTime(t *testing.T) {
	files := map[string]string{"a.php": "<?php\nfunction f($x) { system($x); }\nf($_GET['a']);\n"}
	read := func(p string) ([]byte, error) { return []byte(files[p]), nil }
	for _, c := range []struct {
		name          string
		file, project time.Duration
		fileTime      bool
	}{
		{"the file's limit", time.Nanosecond, time.Hour, true},
		{"the project's clock", time.Hour, time.Nanosecond, false},
	} {
		e := engineForTest(t)
		e.Limits.MaxTime = c.file
		pr := e.NewProject([]string{"a.php"}, read, ProjectOptions{MaxTime: c.project})
		time.Sleep(time.Millisecond)
		res, _ := pr.ScanCallsPart("a.php", []byte(files["a.php"]), nil)
		if !res.Timed || res.FileTime != c.fileTime {
			t.Errorf("%s: timed %v, file time %v, want true and %v", c.name, res.Timed, res.FileTime, c.fileTime)
		}
	}
}
