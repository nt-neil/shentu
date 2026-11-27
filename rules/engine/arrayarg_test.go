package engine

import (
	"strconv"
	"testing"
)

// Input a plugin wraps in array(...) (as [...] already was) on its way to
// another file's sink (v0.5.8 item 1d, CVE-2024-5756's shape).
func TestArrayLiteralAcrossFiles(t *testing.T) {
	e := engineForTest(t)
	db := "<?php\nfunction edit_status($ids = array(), $u = 0) {\n  global $wpdb;\n  $ids_str = implode(',', $ids);\n  return $wpdb->query($wpdb->prepare(\"UPDATE t SET u = %d WHERE id IN({$ids_str})\", $u));\n}\nfunction first($ids) {\n  global $wpdb;\n  return $wpdb->query(\"UPDATE t SET u = 1 WHERE id = {$ids[0]}\");\n}\n"
	helpers := "<?php\nfunction req_data($var = '', $default = '') {\n  return isset($_REQUEST[$var]) ? wp_unslash($_REQUEST[$var]) : $default;\n}\nfunction req_int($var) {\n  return (int) $_REQUEST[$var];\n}\nfunction plugin_version() {\n  return '1.0';\n}\n"
	for _, c := range []struct {
		name   string
		caller string
		at     string
		want   bool
	}{
		{"array() of request input passed to another file's function", "<?php\nrequire 'db.php';\n$ids = array($_REQUEST['db']);\nedit_status($ids, 0);\n", "db.php:5", true},
		{"array() inline, the callee reads an item", "<?php\nrequire 'db.php';\nfirst(array($_GET['id']));\n", "db.php:9", true},
		{"[...] inline (as before)", "<?php\nrequire 'db.php';\nedit_status([$_REQUEST['db']], 0);\n", "db.php:5", true},
		{"array() of a cast", "<?php\nrequire 'db.php';\nedit_status(array((int) $_REQUEST['db']), 0);\n", "db.php:5", false},
		{"array() of literals", "<?php\nrequire 'db.php';\nedit_status(array('1', '2'), 0);\n", "db.php:5", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{"a.php": c.caller, "db.php": db, "h.php": helpers}
			paths := []string{"a.php", "db.php", "h.php"}
			pr := e.NewProject(paths, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{})
			got := false
			var all []string
			for _, p := range paths {
				for _, f := range taintOnly(auditPath(t, e, pr, p, []byte(files[p]))) {
					at := f.Path + ":" + strconv.Itoa(f.Line)
					all = append(all, at+" "+f.RuleID)
					got = got || at == c.at
				}
			}
			if got != c.want {
				t.Errorf("a finding at %s: %v, want %v; all: %v", c.at, got, c.want, all)
			}
		})
	}
}
