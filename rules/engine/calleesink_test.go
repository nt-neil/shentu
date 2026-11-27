package engine

import (
	"slices"
	"strconv"
	"testing"
)

// A call that is itself a sink of the rule, and is reported there, is not
// reported again at the callee's sink of the same rule: wp_redirect($ref) in
// WordPress's wpmu_admin_do_redirect() and the header("Location: ...") inside
// wp_redirect() are one flow (#210's pluggable.php:1542). A callee sink of
// another rule, and a call that is no sink of the rule, still report.
func TestCalleeSinkOfACallThatIsASink(t *testing.T) {
	e := engineForTest(t)
	const caller = "<?php\n$ref = $_GET['ref'];\nwp_redirect($ref);\n"
	for _, c := range []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"wp_redirect, a sink by name, defined in the project: reported once, at the call",
			map[string]string{
				"wp-includes/pluggable.php":     "<?php\nfunction wp_redirect($location, $status = 302) {\n    header(\"Location: $location\", true, $status);\n    return true;\n}\n",
				"wp-includes/ms-deprecated.php": caller,
			},
			[]string{"wp-includes/ms-deprecated.php:3:php-open-redirect-redirect"}},
		{"a callee sink of another rule still reports",
			map[string]string{
				"wp-includes/pluggable.php":     "<?php\nfunction wp_redirect($location) {\n    header(\"Location: $location\");\n    system('logger ' . $location);\n}\n",
				"wp-includes/ms-deprecated.php": caller,
			},
			[]string{"wp-includes/ms-deprecated.php:3:php-open-redirect-redirect", "wp-includes/pluggable.php:4:php-cmdi-shell-exec"}},
		{"a call that is no sink of the rule reports at the callee's sink",
			map[string]string{
				"lib/go.php":  "<?php\nfunction go_to($u) {\n    header(\"Location: $u\");\n}\n",
				"lib/run.php": "<?php\n$ref = $_GET['ref'];\ngo_to($ref);\n",
			},
			[]string{"lib/go.php:3:php-open-redirect-redirect"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			var paths []string
			for p := range c.files {
				paths = append(paths, p)
			}
			slices.Sort(paths)
			read := func(p string) ([]byte, error) { return []byte(c.files[p]), nil }
			pr := e.NewProject(paths, read, ProjectOptions{})
			var got []string
			for _, p := range paths {
				for _, f := range auditPath(t, e, pr, p, []byte(c.files[p])) {
					if f.RuleID == "php-open-redirect-redirect" || f.RuleID == "php-cmdi-shell-exec" {
						got = append(got, f.Path+":"+strconv.Itoa(f.Line)+":"+f.RuleID)
					}
				}
			}
			slices.Sort(got)
			got = slices.Compact(got)
			if !slices.Equal(got, c.want) {
				t.Errorf("reported %v, want %v", got, c.want)
			}
		})
	}
}
