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
			"<?php\n" + R("foreach ($a as $b) { foreach ($b as $c) { $d = $c . $_GET['x']; } }\n", 2000), ErrLimit, CutTime},
		{"nesting", DefaultLimits, nil,
			"<?php\nsystem(" + R("(", 100) + "$_GET['c']" + R(")", 100) + ");\n", ErrLimit, CutNesting},
		{"a rule's call work cap", Limits{MaxTokens: 1 << 20, MaxTime: time.Minute, MaxCallWork: 1}, nil,
			calls, ErrCalls, CutCallWork},
		{"the project's clock", DefaultLimits, &ProjectOptions{MaxTime: time.Nanosecond},
			calls, ErrCalls, CutProject},
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
		if got := CutOf(err); got&c.want == 0 {
			t.Errorf("%s: cut %q, want it to name %q", c.name, got, c.want)
		}
	}
	if CutOf(nil) != 0 || CutOf(ErrPartial) != 0 {
		t.Errorf("no cut: CutOf(nil) = %v, CutOf(ErrPartial) = %v", CutOf(nil), CutOf(ErrPartial))
	}
	if s := (CutTime | CutProject).String(); s != "time,project" {
		t.Errorf("String: %q", s)
	}
}
