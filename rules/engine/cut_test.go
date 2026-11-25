package engine

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// A scan cut short names what cut it (cut.go): ErrLimit or ErrCalls inside a
// *CutError, which CutOf reads back.
func TestCutCauses(t *testing.T) {
	R := strings.Repeat
	calls := "<?php\nfunction f($a) {\n    $b = $a;\n    system($b);\n}\nf($_GET['x']);\n"
	for _, c := range []struct {
		name   string
		limits Limits
		proj   *ProjectOptions
		src    string
		err    error
		want   Cut
	}{
		{"token cap", Limits{MaxTokens: 1000, MaxTime: time.Minute}, nil,
			"<?php\n" + R("$a = $b . $c;\n", 1000), ErrLimit, CutTokens},
		{"clock", Limits{MaxTokens: 1 << 20, MaxTime: time.Nanosecond}, nil,
			"<?php\n" + R("foreach ($a as $b) { foreach ($b as $c) { $d = $c . $_GET['x']; } }\n", 2000), ErrLimit, CutClock},
		{"the file's work cap", Limits{MaxTokens: 1 << 20, MaxWork: 1000, MaxTime: time.Minute}, nil,
			"<?php\n" + R("foreach ($a as $b) { foreach ($b as $c) { $d = $c . $_GET['x']; } }\n", 2000), ErrLimit, CutWork},
		{"nesting", DefaultLimits, nil,
			"<?php\nsystem(" + R("(", 100) + "$_GET['c']" + R(")", 100) + ");\n", ErrLimit, CutNesting},
		{"a rule's call work cap", Limits{MaxTokens: 1 << 20, MaxTime: time.Minute, MaxCallWork: 1}, nil,
			calls, ErrCalls, CutCallWork},
		{"the project's clock", DefaultLimits, &ProjectOptions{MaxTime: time.Nanosecond},
			calls, ErrCalls, CutProject | CutClock},
	} {
		e := engineForTest(t)
		e.Limits = c.limits
		var err error
		if c.proj != nil {
			pr := e.NewProject([]string{"a.php"}, func(string) ([]byte, error) { return []byte(c.src), nil }, *c.proj)
			_, err = pr.Scan("a.php", []byte(c.src))
		} else {
			_, err = e.Scan("php", "a.php", []byte(c.src))
		}
		if !errors.Is(err, c.err) {
			t.Errorf("%s: err %v, want %v", c.name, err, c.err)
			continue
		}
		if got := CutOf(err); got&c.want != c.want {
			t.Errorf("%s: cut %q, want it to name %q", c.name, got, c.want)
		} else if c.want&CutClock == 0 && got&CutClock != 0 {
			t.Errorf("%s: cut %q: the clock is only a safety net, not what cut this", c.name, got)
		}
	}
	// The project's work cap is checked before each file: past it, the next
	// file's calls no longer cross files, and that is what it names.
	e := engineForTest(t)
	src := map[string]string{"a.php": calls, "b.php": "<?php\nf($_GET['y']);\n"}
	pr := e.NewProject([]string{"a.php", "b.php"}, func(p string) ([]byte, error) { return []byte(src[p]), nil }, ProjectOptions{MaxWork: 1})
	if _, err := pr.Scan("a.php", []byte(src["a.php"])); err != nil {
		t.Errorf("a.php, within the project's work cap: %v", err)
	}
	_, timed, err := pr.ScanCallsTimed("b.php", []byte(src["b.php"]))
	if !errors.Is(err, ErrCalls) || CutOf(err) != CutProject|CutProjectWork || !timed {
		t.Errorf("b.php, past the project's work cap: err %v, cut %q, timed %v; want ErrCalls, project,project-work, timed (a later audit goes on)", err, CutOf(err), timed)
	}
	if CutOf(nil) != 0 || CutOf(ErrPartial) != 0 {
		t.Errorf("no cut: CutOf(nil) = %v, CutOf(ErrPartial) = %v", CutOf(nil), CutOf(ErrPartial))
	}
	if s := (CutClock | CutProject | CutAmbiguous | CutProjectWork).String(); s != "safety-clock,project,ambiguous-call,project-work" {
		t.Errorf("String: %q", s)
	}
}
