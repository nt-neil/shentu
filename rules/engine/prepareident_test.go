package engine

import (
	"strconv"
	"strings"
	"testing"
)

// sqlPlace is where a value stands in SQL text.
type sqlPlace int

const (
	sqlQuoted sqlPlace = iota // inside a string literal ('...', "...")
	sqlBare                   // standing alone: a number, a keyword's operand
	sqlIdent                  // inside backticks: a column or table name
)

// sqlQuoteContexts are the places a value can take in SQL text, shared by the
// tests of what quoting protects: prepare()'s %s here, esc_sql() inside
// quotes later. "{}" marks the value.
var sqlQuoteContexts = []struct {
	name, sql string
	place     sqlPlace
}{
	{"between single quotes", "SELECT * FROM t WHERE a = '{}'", sqlQuoted},
	{"between double quotes", `SELECT * FROM t WHERE a = "{}"`, sqlQuoted},
	{"in an IN list", "SELECT * FROM t WHERE a IN ('{}')", sqlQuoted},
	{"in a LIKE pattern", "SELECT * FROM t WHERE a LIKE '%{}%'", sqlQuoted},
	{"standing alone", "SELECT * FROM t WHERE a = {}", sqlBare},
	{"in an IN list without quotes", "SELECT * FROM t WHERE a IN ({})", sqlBare},
	{"in backticks", "SELECT `{}` FROM t", sqlIdent},
	{"after ORDER BY", "SELECT * FROM t ORDER BY {}", sqlBare},
	{"after ORDER BY, in backticks", "SELECT * FROM t ORDER BY `{}`", sqlIdent},
	{"in LIMIT", "SELECT * FROM t LIMIT {}", sqlBare},
	{"in backticks inside an SQL string", "UPDATE t SET note = 'a `{}` b'", sqlQuoted},
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
		q := strings.ReplaceAll(strings.ReplaceAll(c.sql, "%", "%%"), "{}", "%s") // a literal % is %% in a format
		cases = append(cases, tc{"%s " + c.name,
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$r = $wpdb->get_results($wpdb->prepare('" + strings.ReplaceAll(q, "'", "\\'") + "', $_GET['v']));\n"},
			"a.php", 3, c.place == sqlIdent})
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
		tc{"a numbered placeholder past int's range",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare('UPDATE t SET `%18446744073709551615$s` = 1, `%s` = 2', $_GET['c']));\n"},
			"a.php", 3, true},
		tc{"%0$s names no value",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare('UPDATE t SET `%0$s` = 1 WHERE a = %s', $_GET['c']));\n"},
			"a.php", 3, false},
		tc{"a backtick in a /* */ comment before a bare %s (review S-265-1)",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare('SELECT * FROM t /* the `x` column */ WHERE a = %s', $_GET['c']));\n"},
			"a.php", 3, false},
		tc{"a backtick in a -- comment before a bare %s",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare('SELECT * FROM t -- the `x\nWHERE a = %s', $_GET['c']));\n"},
			"a.php", 3, false},
		tc{"a backtick in a # comment before a bare %s",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare('SELECT * FROM t # the `x\nWHERE a = %s', $_GET['c']));\n"},
			"a.php", 3, false},
		tc{"a quote in a comment before %s in backticks",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare('/* don\\'t */ UPDATE t SET `%s` = 1', $_GET['c']));\n"},
			"a.php", 3, true},
		tc{"\\n in a '...' string is no line end: the -- comment goes on",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare('SELECT 1 -- note\\n, `%s` FROM t', $_GET['c']));\n"},
			"a.php", 3, false},
		tc{"\\n in a \"...\" string ends the -- comment",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare(\"SELECT 1 -- note\\n, `%s` FROM t\", $_GET['c']));\n"},
			"a.php", 3, true},
		tc{"\\' in a \"...\" string stays two characters",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare(\"UPDATE t SET a = \\' , `%s` = 1\", $_GET['c']));\n"},
			"a.php", 3, true},
		tc{"a /*! */ comment is SQL MySQL runs",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare('SELECT /*! `%s` */ FROM t', $_GET['c']));\n"},
			"a.php", 3, true},
		tc{"\\\" in a '...' string stays two characters (review N-266-1)",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare('SELECT * FROM t WHERE a = \"x\\\" AND `%s`', $_GET['c']));\n"},
			"a.php", 3, false},
		tc{"a nowdoc keeps \\' as written (review N-266-1)",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$q = <<<'SQL'\nSELECT * FROM t WHERE a = 'x\\' AND `%s`\nSQL;\n$wpdb->query($wpdb->prepare($q, $_GET['c']));\n"},
			"a.php", 6, false},
		tc{"\\x60 in a \"...\" string is a backtick (review N-266-1)",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare(\"SELECT \\x60%s\\x60 FROM t\", $_GET['c']));\n"},
			"a.php", 3, true},
		tc{"a placeholder in a comment still takes its value (review N-266-2)",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare('/* %s */ SELECT `%s` FROM t', 'a', $_GET['c']));\n"},
			"a.php", 3, true},
		tc{"a /*!50000 */ comment is SQL (review S-266-1)",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare('SELECT /*!50000 `%s` */ FROM t', $_GET['c']));\n"},
			"a.php", 3, true},
		tc{"\\u{60} in a \"...\" string is a backtick (review S-266-2)",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare(\"SELECT \\u{60}%s\\u{60} FROM t\", $_GET['c']));\n"},
			"a.php", 3, true},
		tc{"a quote in a comment started by --\\r, then %s in backticks",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare(\"SELECT 1 --\\r don't\\nFROM `%s`\", $_GET['c']));\n"},
			"a.php", 3, true},
		tc{"a quote in a comment started by --\\v, then %s in backticks",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare(\"SELECT 1 --\\v don't\\nFROM `%s`\", $_GET['c']));\n"},
			"a.php", 3, true},
		tc{"a quote in a comment started by --\\f, then %s in backticks",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare(\"SELECT 1 --\\f don't\\nFROM `%s`\", $_GET['c']));\n"},
			"a.php", 3, true},
		tc{"-- then a part not written out may start a comment",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare(\"SELECT 1 --\" . $sep . \" don't\\nFROM `%s`\", $_GET['c']));\n"},
			"a.php", 3, true},
		tc{"-- then a part not written out hides no %s in backticks after it",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare(\"UPDATE t SET a = 1 --\" . $sep . \" , `%s` = 2\", $_GET['c']));\n"},
			"a.php", 3, true},
		tc{"two -- before parts not written out, only the first a comment",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare(\"SELECT 1 --\" . $a . \" 'q\\n, 2 --\" . $b . \" , `%s`\", $_GET['c']));\n"},
			"a.php", 3, true},
		tc{"more -- before parts not written out than are read both ways: every %s counts",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare(\"SELECT 1 --\" . $a . \"--\" . $a . \"--\" . $a . \"--\" . $a . \"--\" . $a . \"--\" . $a . \"--\" . $a . \" %s\", $_GET['c']));\n"},
			"a.php", 3, true},
		tc{"seven -- before parts not written out, all inside an SQL string (review D12)",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare(\"SELECT * FROM t WHERE a = '--{$x}--{$x}--{$x}--{$x}--{$x}--{$x}--{$x} %s'\", $_GET['c']));\n"},
			"a.php", 3, false},
		tc{"a -- only met once the -- before it is a comment",
			map[string]string{"a.php": "<?php\nglobal $wpdb;\n$wpdb->query($wpdb->prepare(\"SELECT 1 --\" . $a . \" \\\"q\\n, 2 --\" . $b . \" 'z\\nFROM `%s`\", $_GET['c']));\n"},
			"a.php", 3, true},
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
