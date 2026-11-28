package engine

import (
	"testing"

	"github.com/nt-neil/shentu/rules"
)

// A foreach key of an array whose keys are all the code's literals is no
// input, even when its values are (litKeys). A key that is input, or an array
// the code may have rewritten where the analysis does not follow, still is.
func TestLitKeysForeach(t *testing.T) {
	arg4 := 4
	e, err := New([]rules.Rule{{ID: "hdr", Lang: "php", Class: "crlf", CWE: "CWE-93", Severity: "medium", Title: "t",
		Sources: []string{"$_POST", "$_GET"}, Sinks: []string{"mail("}, Sanitizers: []string{},
		Args: []rules.Args{{Sinks: []string{"mail("}, Arg: &arg4}}}})
	if err != nil {
		t.Fatal(err)
	}
	loop := "foreach ($u as $k => $v) {\n  mail('a@example.org', 'S', 'B', \"X-Key: {$k}\");\n}"
	for _, c := range []struct {
		name, body string
		want       bool
	}{
		{"[...] with literal keys", "$u = ['db.host' => $_POST['h'], 'db.pass' => $_POST['p']];\n" + loop, false},
		{"array(...) with literal keys", "$u = array('db.host' => $_POST['h'], 3 => $_POST['p']);\n" + loop, false},
		{"literal keys written by literal key since", "$u = ['a' => $_POST['h']];\n$u['b'] = $_POST['p'];\n" + loop, false},
		{"no keys written (a list)", "$u = [$_POST['h'], $_POST['p']];\n" + loop, false},
		{"the value itself is still input", "$u = ['db.host' => $_POST['h']];\nforeach ($u as $k => $v) {\n  mail('a@example.org', 'S', 'B', \"X-Val: {$v}\");\n}", true},
		{"$_POST's keys", "foreach ($_POST as $k => $v) {\n  mail('a@example.org', 'S', 'B', \"X-Key: {$k}\");\n}", true},
		{"array_keys($_GET)", "foreach (array_keys($_GET) as $i => $k) {\n  mail('a@example.org', 'S', 'B', \"X-Key: {$k}\");\n}", true},
		{"then written under a computed key", "$u = ['a' => $_POST['h']];\n$k0 = $_GET['k'];\n$u[$k0] = $_POST['p'];\n" + loop, true},
		{"then given $_POST whole", "$u = ['a' => $_POST['h']];\n$u = $_POST;\n" + loop, true},
		{"extract() in the function", "$u = ['a' => $_POST['h']];\nextract($_POST);\n" + loop, true},
		{"passed by reference to a function that writes keys", "$u = ['a' => $_POST['h']];\nfill($u);\n" + loop + "\n}\nfunction fill(&$a) {\n  $a[$_GET['k']] = 1;", true},
		{"one path written under a computed key with no input", "if (isset($_GET['x'])) {\n  $u = ['a' => $_POST['h']];\n} else {\n  $u = [];\n  $u[$_GET['k']] = 1;\n}\n" + loop, true},
		{"one path an empty literal", "if (isset($_GET['x'])) {\n  $u = ['a' => $_POST['h']];\n} else {\n  $u = [];\n}\n" + loop, false},
		{"then a key from input, the value not", "$u = ['a' => $_POST['h']];\n$u[$_GET['k']] = 1;\n" + loop, true},
		{"a ternary whose other side has a computed key", "$w = [];\n$w[$_GET['k']] = 1;\n$u = isset($_GET['x']) ? ['a' => $_POST['h']] : $w;\n" + loop, true},
		{"one path not literal", "if (isset($_GET['x'])) {\n  $u = ['a' => $_POST['h']];\n} else {\n  $u = $_POST;\n}\n" + loop, true},
		{"a computed key in the literal", "$u = [$_GET['k'] => $_POST['h']];\n" + loop, true},
		{"a spread in the literal", "$u = ['a' => $_POST['h'], ...$_POST];\n" + loop, true},
		{"an interpolated key in the literal", "$k0 = $_GET['k'];\n$u = [\"k{$k0}\" => $_POST['h']];\n" + loop, true},
		{"a heredoc key in the literal", "$k0 = $_GET['k'];\n$u = [<<<EOT\nk{$k0}\nEOT => $_POST['h']];\n" + loop, true},
		{"a copy of an array passed by reference", "$u = ['a' => $_POST['h']];\nfill($u);\n$b = $u;\nforeach ($b as $k => $v) {\n  mail('a@example.org', 'S', 'B', \"X-Key: {$k}\");\n}\n}\nfunction fill(&$a) {\n  $a[$_GET['k']] = 1;", true},
		{"a copy of a literal", "$u = ['a' => $_POST['h']];\n$b = $u;\nforeach ($b as $k => $v) {\n  mail('a@example.org', 'S', 'B', \"X-Key: {$k}\");\n}", false},
		{"a double-quoted key with no variable", "$u = [\"db.host\" => $_POST['h']];\n" + loop, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := "<?php\nfunction f() {\n" + c.body + "\n}\nadd_action('wp_ajax_x', 'f');\n"
			pr := e.NewProject([]string{"a.php"}, func(string) ([]byte, error) { return []byte(src), nil }, ProjectOptions{})
			got := false
			for _, f := range taintOnly(auditPath(t, e, pr, "a.php", []byte(src))) {
				got = got || f.RuleID == "hdr"
			}
			if got != c.want {
				t.Errorf("reported %v, want %v", got, c.want)
			}
		})
	}
}
