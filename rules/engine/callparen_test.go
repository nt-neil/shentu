package engine

import (
	"strconv"
	"testing"

	"github.com/nt-neil/shentu/rules"
)

// callParen is the "(" of the call a pattern names: a pattern that starts
// with a name and its "(" and leaves more than one "(" open is that call,
// not the innermost one it writes out (str_replace(array("\r", "\n": the
// str_replace, so a sanitizer covers the whole call).
func TestCallParen(t *testing.T) {
	for _, c := range []struct {
		lang, raw string
		want      int
	}{
		{"php", "mail(", 1},
		{"php", `str_replace(array("\r", "\n"`, 1},
		{"php", "json_decode(file_get_contents('php://input'", 1},
		{"php", "$wpdb->prepare(", 3},
		{"php", "->where(", 2},
		{"python", "subprocess.run([", 3},
		{"python", "shlex.split(request.get_json(", 7}, // a name, then ".": the innermost, as before
		{"js", "exec(", 1},
	} {
		p, err := compilePattern(c.lang, c.raw, false)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.callParen(); got != c.want {
			t.Errorf("%s %q: callParen %d, want %d", c.lang, c.raw, got, c.want)
		}
	}
}

// On the product path: a sanitizer written with an inner array( call covers
// the whole call, as the [...] form does; a source written so (mongo's
// json_decode(file_get_contents('php://input') still reports.
func TestCallParenSanitizerAndSource(t *testing.T) {
	arg4 := 4
	e, err := New([]rules.Rule{{ID: "hdr", Lang: "php", Class: "crlf", CWE: "CWE-93", Severity: "medium", Title: "t",
		Sources: []string{"$_POST"}, Sinks: []string{"mail("}, Sanitizers: []string{`str_replace(array("\r", "\n"`, `str_replace(["\r", "\n"]`},
		Args: []rules.Args{{Sinks: []string{"mail("}, Arg: &arg4}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, body string
		want       bool
	}{
		{"array( form", "$v = str_replace(array(\"\\r\", \"\\n\"), '', $_POST['v']);\nmail('a@example.org', 'S', 'B', 'X-Ref: ' . $v);", false},
		{"[...] form", "$v = str_replace([\"\\r\", \"\\n\"], '', $_POST['v']);\nmail('a@example.org', 'S', 'B', 'X-Ref: ' . $v);", false},
		{"no sanitizer", "$v = $_POST['v'];\nmail('a@example.org', 'S', 'B', 'X-Ref: ' . $v);", true},
		{"the input outside the sanitizer's call", "$v = str_replace(array(\"\\r\", \"\\n\"), '', $_POST['a']) . $_POST['b'];\nmail('a@example.org', 'S', 'B', 'X-Ref: ' . $v);", true},
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
	m := engineForTest(t)
	src := "<?php\n$f = json_decode(file_get_contents('php://input'), true);\n$u = $db->users->findOne(['name' => $f['name']]);\n"
	pr := m.NewProject([]string{"a.php"}, func(string) ([]byte, error) { return []byte(src), nil }, ProjectOptions{})
	var all []string
	got := false
	for _, f := range taintOnly(auditPath(t, m, pr, "a.php", []byte(src))) {
		all = append(all, strconv.Itoa(f.Line)+" "+f.RuleID)
		got = got || f.RuleID == "php-nosqli-mongo-query" && f.Line == 3
	}
	if !got {
		t.Errorf("php-nosqli-mongo-query not at a.php:3 with json_decode(file_get_contents('php://input')); all: %v", all)
	}
}
