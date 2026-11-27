package engine

import (
	"strconv"
	"strings"
	"testing"
)

// WordPress checks the engine reads as checks in every rule or in the rules
// that list them (v0.5.8 item 1d): a check holds only where its result guards
// the value, never when the result is only kept or logged.
func TestWordPressChecks(t *testing.T) {
	e := engineForTest(t)
	for _, c := range []struct {
		name, src, class string
		line             int
		want             bool
	}{
		{"taxonomy_exists() guards the echo", "<?php\n$t = $_GET['t'];\nif (taxonomy_exists($t)) {\n  echo $t;\n}\n", "xss", 4, false},
		{"post_type_exists() false ends the request", "<?php\n$pt = $_GET['pt'];\nif (!post_type_exists($pt)) {\n  wp_die();\n}\necho $pt;\n", "xss", 6, false},
		{"taxonomy_exists() kept in a variable and logged", "<?php\n$t = $_GET['t'];\n$ok = taxonomy_exists($t);\nerror_log((string) $ok);\necho $t;\n", "xss", 5, true},
		{"taxonomy_exists() guards another statement", "<?php\n$t = $_GET['t'];\nif (taxonomy_exists($t)) {\n  do_action('x');\n}\necho $t;\n", "xss", 6, true},
		{"is_serialized_string() guards maybe_unserialize()", "<?php\n$v = $_POST['v'];\nif (is_serialized_string($v)) {\n  $x = maybe_unserialize($v);\n}\n", "deserialization", 4, false},
		{"is_serialized_string() guards unserialize()", "<?php\n$v = $_POST['v'];\nif (is_serialized_string($v)) {\n  $x = unserialize($v);\n}\n", "deserialization", 4, false},
		{"is_serialized_string() kept in a variable and logged", "<?php\n$v = $_POST['v'];\n$ok = is_serialized_string($v);\nerror_log((string) $ok);\n$x = unserialize($v);\n", "deserialization", 5, true},
		{"is_serialized() lets an object through", "<?php\n$v = $_POST['v'];\nif (is_serialized($v)) {\n  $x = unserialize($v);\n}\n", "deserialization", 4, true},
		{"wp_upload_bits() of a name ending with a written extension", "<?php\n$n = $_FILES['f']['name'];\nwp_upload_bits($n . '.txt', null, 'x');\n", "file-upload", 3, false},
		{"wp_upload_bits() of a name ending with $ext only ever an extension (image.php shape)", "<?php\n$ext = '.jpg';\nif ($_POST['m'] === 'image/png') {\n  $ext = '.png';\n}\n$basename = str_replace('.', '-', $_FILES['f']['name']) . '-image' . $ext;\nwp_upload_bits($basename, '', 'x');\n", "file-upload", 7, false},
		{"wp_upload_bits() of the client's name", "<?php\n$n = $_FILES['f']['name'];\nwp_upload_bits($n, null, 'x');\n", "file-upload", 3, true},
		{"$ext given request input on a path", "<?php\n$ext = '.jpg';\nif (isset($_POST['e'])) {\n  $ext = $_POST['e'];\n}\n$basename = 'a' . $ext;\nwp_upload_bits($basename, '', 'x');\n", "file-upload", 7, true},
		{"a name ending with an extension, then appended to", "<?php\n$basename = $_FILES['f']['name'] . '.png';\n$basename .= $_POST['x'];\nwp_upload_bits($basename, '', 'x');\n", "file-upload", 4, true},
		{"the extension taken from the client's name", "<?php\n$ext = pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION);\nwp_upload_bits('a.' . $ext, '', 'x');\n", "file-upload", 3, true},
		{"a name ending with .php is no fixed type", "<?php\n$n = $_FILES['f']['name'];\nwp_upload_bits($n . '.php', null, 'x');\n", "file-upload", 3, true},
		{"$ext given .png, then appended to", "<?php\n$ext = '.png';\n$ext .= $_POST['x'];\nwp_upload_bits($_FILES['f']['name'] . $ext, '', 'x');\n", "file-upload", 4, true},
		{"$ext a foreach target", "<?php\n$ext = '.png';\nforeach ($_POST['e'] as $ext) {}\nwp_upload_bits($_FILES['f']['name'] . $ext, '', 'x');\n", "file-upload", 4, true},
		{"$ext set by extract()", "<?php\n$ext = '.png';\nextract($_POST);\nwp_upload_bits($_FILES['f']['name'] . $ext, '', 'x');\n", "file-upload", 4, true},
		{"$basename destructured from the request", "<?php\n$basename = 'a.png';\n[$basename] = $_POST['n'];\nwp_upload_bits($basename, '', 'x');\n", "file-upload", 4, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			pr := e.NewProject([]string{"a.php"}, func(string) ([]byte, error) { return []byte(c.src), nil }, ProjectOptions{})
			got := false
			var all []string
			for _, f := range taintOnly(auditPath(t, e, pr, "a.php", []byte(c.src))) {
				all = append(all, strconv.Itoa(f.Line)+" "+f.RuleID)
				got = got || f.Line == c.line && strings.Contains(f.RuleID, "-"+c.class+"-")
			}
			if got != c.want {
				t.Errorf("a %s finding at line %d: %v, want %v; all: %v", c.class, c.line, got, c.want, all)
			}
		})
	}
}
