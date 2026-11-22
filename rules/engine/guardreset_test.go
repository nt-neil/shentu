package engine

import (
	"slices"
	"testing"
)

// c3 Q1: a check that fails, followed by unset or a reset to a constant, leaves
// a value that carries no input; is_numeric and the other number checks
// validate in every rule, as number casts do. The controls must still report.
func TestGuardResetAndUnset(t *testing.T) {
	e := engineForTest(t)
	for _, c := range []struct {
		name, src string
		want      []string
	}{
		{"reset to a constant", "<?php\n$p = $_GET['x'];\nif (!is_numeric($p)) { $p = 0; }\nsystem('ls ' . $p);\n", nil},
		{"reset an element", "<?php\n$c = $_GET;\nif (!is_numeric($c['port'])) { $c['port'] = 0; }\nsystem('ls ' . $c['port']);\n", nil},
		{"reset a property", "<?php\nclass K {\n  public $p;\n  function f() {\n    $this->p = $_GET['x'];\n    if (!in_array($this->p, array('a'), true)) { $this->p = 'a'; }\n    system('ls ' . $this->p);\n  }\n}\n", nil},
		{"reset a request element", "<?php\nif (!in_array($_POST['m'], array('a', 'b'), true)) { $_POST['m'] = 'a'; }\nsystem('ls ' . $_POST['m']);\n", nil},
		{"unset an element", "<?php\n$c = $_GET;\nif (!is_numeric($c['port'])) { unset($c['port']); }\nsystem('ls ' . $c['port']);\n", nil},
		{"unset a variable", "<?php\n$p = $_GET['x'];\nif (!in_array($p, array('a', 'b'), true)) { unset($p); }\nsystem('ls ' . $p);\n", nil},
		{"list(), then unset (wp-admin/includes/file.php)", "<?php\n$c = $_GET;\nlist($c['h'], $c['port']) = explode(':', $c['h'], 2);\nif (!is_numeric($c['port'])) { unset($c['port']); }\n$port = $c['port'] ?? '';\nsystem('ls ' . $port);\n", nil},
		{"empty() || a failed check", "<?php\n$a = $_GET;\nif (empty($a['d']) || !in_array($a['d'], array('x', 'y'), true)) { unset($a['d']); }\nsystem('ls ' . $a['d']);\n", nil},
		{"the number check in the positive branch", "<?php\n$p = $_GET['x'];\nif (is_numeric($p)) { system('ls ' . $p); }\n", nil},
		// controls
		{"input written after the reset (control)", "<?php\n$p = $_GET['y'];\nif (!is_numeric($p)) { $p = 0; }\n$p = $_GET['x'];\nsystem('ls ' . $p);\n", []string{"5"}},
		{"input written after the unset (control)", "<?php\n$c = $_GET;\nif (!is_numeric($c['port'])) { unset($c['port']); }\n$c['port'] = $_GET['p'];\nsystem('ls ' . $c['port']);\n", []string{"5"}},
		{"a failed check with no reset (control)", "<?php\n$c = $_GET;\nif (!is_numeric($c['port'])) { $z = 0; }\nsystem('ls ' . $c['port']);\n", []string{"4"}},
		{"another key unset (control)", "<?php\n$c = $_GET;\nif (!is_numeric($c['port'])) { unset($c['q']); }\nsystem('ls ' . $c['port']);\n", []string{"4"}},
		{"a key that is not a literal (control)", "<?php\n$c = $_GET;\n$k = $_GET['k'];\nif (!is_numeric($c['port'])) { unset($c[$k]); }\nsystem('ls ' . $c['port']);\n", []string{"5"}},
		{"the value used where the check failed (control)", "<?php\n$p = $_GET['x'];\nif (!is_numeric($p)) { system('ls ' . $p); }\n", []string{"3"}},
		{"x && a failed check (control)", "<?php\n$a = $_GET;\nif ($z && !in_array($a['d'], array('x', 'y'), true)) { $a['d'] = 'x'; }\nsystem('ls ' . $a['d']);\n", []string{"4"}},
		{"a number check of a transformed value (control)", "<?php\n$p = $_GET['x'];\nif (is_numeric(sanitize_text_field($p))) { system('ls ' . $p); }\n", []string{"3"}},
		{"another value checked (control)", "<?php\n$p = $_GET['x'];\n$q = $_GET['y'];\nif (!is_numeric($q)) { $q = 0; }\nsystem('ls ' . $p);\n", []string{"5"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, _, err := e.ScanTimed("php", "a.php", []byte(c.src))
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, x := range f {
				if x.RuleID == "php-cmdi-shell-exec" {
					got = append(got, itoa(x.Line))
				}
			}
			slices.Sort(got)
			got = slices.Compact(got)
			if !slices.Equal(got, c.want) {
				t.Errorf("reported lines %v, want %v", got, c.want)
			}
		})
	}
}

// The number checks validate for an attribute too: wp-admin/includes/file.php
// echoes the port into the hostname field once is_numeric has failed and the
// key been unset.
func TestNumberCheckAttribute(t *testing.T) {
	e := engineForTest(t)
	for _, c := range []struct {
		name, src string
		want      bool
	}{
		{"is_numeric, then reset", "<?php\n$p = $_GET['x'];\nif (!is_numeric($p)) { $p = 0; }\n?><input value=\"<?php echo $p; ?>\">\n", false},
		{"no check (control)", "<?php\n$p = $_GET['x'];\n?><input value=\"<?php echo $p; ?>\">\n", true},
	} {
		f, _, err := e.ScanTimed("php", "a.php", []byte(c.src))
		if err != nil {
			t.Fatal(err)
		}
		got := false
		for _, x := range f {
			got = got || x.RuleID == "php-xss-echo-attribute"
		}
		if got != c.want {
			t.Errorf("%s: reported %v, want %v", c.name, got, c.want)
		}
	}
}
