package engine

import (
	"strconv"
	"strings"
	"testing"
)

// sqlQuoteContexts are the places a value can take in SQL text, shared by the
// tests of what quoting protects: prepare()'s %s here, esc_sql() inside
// quotes later. "{}" marks the value; backtick tells an identifier.
var sqlQuoteContexts = []struct {
	name, sql string
	backtick  bool
}{
	{"between single quotes", "SELECT * FROM t WHERE a = '{}'", false},
	{"standing alone", "SELECT * FROM t WHERE a = {}", false},
	{"in backticks", "SELECT `{}` FROM t", true},
	{"after ORDER BY", "SELECT * FROM t ORDER BY {}", false},
	{"after ORDER BY, in backticks", "SELECT * FROM t ORDER BY `{}`", true},
	{"in LIMIT", "SELECT * FROM t LIMIT {}", false},
	{"in backticks inside an SQL string", "UPDATE t SET note = 'a `{}` b'", false},
}

// prepare()'s %s is quoted as a string; inside backticks it is an identifier
// the quoting does not protect (php-sqli-prepare-identifier, identArgs).
func TestPrepareIdentifier(t *testing.T) {
	e := engineForTest(t)
	type tc struct {
		name  string
		files map[string]string
		scan  string
		line  int
		want  bool
	}
	var cases []tc
	for _, c := range sqlQuoteContexts {
		q := strings.ReplaceAll(c.sql, "{}", "%s")
		cases = append(cases, tc{"%s " + c.name,
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$r = $wpdb->get_results($wpdb->prepare(\"" + q + "\", $_GET['v']));\n"},
			"a.php", 3, c.backtick})
	}
	cases = append(cases,
		tc{"numbered placeholders in backticks (notificationx shape)",
			map[string]string{"a.php": "<?php\nfunction track($request) {\n  global $wpdb;\n  $col = $request->get_params()['type'];\n  $wpdb->query($wpdb->prepare('UPDATE %1$s SET `%2$s` = `%3$s` + 1 WHERE id = %4$d', 'stats', $col, $col, 1));\n}\n"},
			"a.php", 5, true},
		tc{"the format in a variable",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$q = \"UPDATE t SET `%s` = 1\";\n$wpdb->query($wpdb->prepare($q, $_POST['c']));\n"},
			"a.php", 4, true},
		tc{"a value in a function of another file",
			map[string]string{
				"a.php": "<?php\nrequire 'b.php';\nbump($_GET['col']);\n",
				"b.php": "<?php\nfunction bump($col) {\n  global $wpdb;\n  return $wpdb->query($wpdb->prepare('UPDATE %1$s SET `%2$s` = `%2$s` + 1', 'stats', $col));\n}\n"},
			"a.php", 4, true},
		tc{"the backticked value is a literal, the input is quoted",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare(\"UPDATE t SET `%s` = %s\", 'status', $_GET['v']));\n"},
			"a.php", 3, false},
		tc{"sanitize_key() in backticks",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare(\"UPDATE t SET `%s` = 1\", sanitize_key($_GET['c'])));\n"},
			"a.php", 3, false},
		tc{"%d in backticks",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare(\"UPDATE t SET `%d` = 1\", $_GET['c']));\n"},
			"a.php", 3, false},
		tc{"%i, WordPress's identifier placeholder",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare(\"UPDATE t SET %i = 1\", $_GET['c']));\n"},
			"a.php", 3, false},
		tc{"%% before the placeholder",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare(\"SELECT * FROM t WHERE a LIKE '50%%' AND `%s` = 1\", $_GET['c']));\n"},
			"a.php", 3, true},
	)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var paths []string
			for p := range c.files {
				paths = append(paths, p)
			}
			pr := e.NewProject(paths, func(p string) ([]byte, error) { return []byte(c.files[p]), nil }, ProjectOptions{})
			got := false
			var all []string
			for _, p := range paths {
				for _, f := range auditPath(t, e, pr, p, []byte(c.files[p])) {
					all = append(all, f.Path+":"+strconv.Itoa(f.Line)+" "+f.RuleID)
					got = got || strings.HasPrefix(f.RuleID, "php-sqli-") && f.Line == c.line && (len(c.files) == 1 || f.Path != c.scan)
				}
			}
			if got != c.want {
				t.Errorf("an sqli finding at line %d: %v, want %v; all: %v", c.line, got, c.want, all)
			}
		})
	}
}
