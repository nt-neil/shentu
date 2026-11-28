package tools

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Through app_code_audit: an object's property that was an array is still
// reported once a method or a copy of the object may have rewritten it.
func TestAppCodeAuditNotArrayMembers(t *testing.T) {
	const rule = "php-deserialization-wp-maybe-unserialize"
	for _, c := range []struct {
		name, src string
		want      bool
	}{
		{"$this->x rewritten by a method", "<?php\nclass C {\n  function run() {\n    $this->x = [$_POST['a']];\n    $this->setx();\n    maybe_unserialize($this->x);\n  }\n  function setx() {\n    $this->x = $_POST['b'];\n  }\n}\nadd_action('wp_ajax_x', [new C, 'run']);\n", true},
		{"an object copied, then its property written", "<?php\nadd_action('wp_ajax_x', function () {\n  $o = new stdClass();\n  $o->p = [$_POST['a']];\n  $q = $o;\n  $q->p = $_POST['b'];\n  maybe_unserialize($o->p);\n});\n", true},
		{"a local array", "<?php\nadd_action('wp_ajax_x', function () {\n  $a = [$_POST['a']];\n  maybe_unserialize($a);\n});\n", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir, _ := filepath.EvalSymlinks(t.TempDir())
			if err := os.WriteFile(filepath.Join(dir, "a.php"), []byte(c.src), 0o644); err != nil {
				t.Fatal(err)
			}
			res := AppCodeAudit(context.Background(), []string{dir}, nil)
			got := false
			for _, f := range res.Findings {
				got = got || f.Kind == "injection" && f.Rule == rule
			}
			if got != c.want {
				t.Errorf("%s reported: %v, want %v", rule, got, c.want)
			}
		})
	}
}
