package engine

import "testing"

// scanProject scans every file of a project and returns what each found.
func scanProject(t *testing.T, files map[string]string, order ...string) (found []Finding, errs map[string]error) {
	t.Helper()
	e := engineForTest(t)
	pr := e.NewProject(order, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{})
	errs = map[string]error{}
	for _, p := range order {
		fs, err := pr.Scan(p, []byte(files[p]))
		found = append(found, fs...)
		errs[p] = err
	}
	return found, errs
}

// A qualified class name right after a keyword (return App\Run::cmd()) is the
// class, not "returnApp\Run" (P4 of the WordPress coverage work: http.php's
// return WpOrg\Requests\Requests::has_capabilities()).
func TestProjectQualifiedNameAfterKeyword(t *testing.T) {
	files := map[string]string{
		"a.php": "<?php\nfunction g($v) {\n\treturn App\\Run::cmd($v);\n}\ng($_GET['x']);\n",
		"b.php": "<?php\nnamespace App;\nclass Run {\n\tstatic function cmd($x) {\n\t\tsystem('ls ' . $x);\n\t}\n}\n",
		// The same short name in another namespace: only the qualified name tells.
		"c.php": "<?php\nnamespace Old;\nclass Run {\n\tstatic function cmd($x) {\n\t\tsystem('ls ' . $x);\n\t}\n}\n",
	}
	found, errs := scanProject(t, files, "a.php", "b.php", "c.php")
	if len(found) != 1 || found[0].Path != "b.php" || found[0].Line != 5 || errs["a.php"] != nil {
		t.Errorf("vulnerable: %v %v, want b.php:5 and a.php followed to the end", found, errs)
	}
	files["b.php"] = "<?php\nnamespace App;\nclass Run {\n\tstatic function cmd($x) {\n\t\tsystem('ls ' . escapeshellarg($x));\n\t}\n}\n"
	found, errs = scanProject(t, files, "a.php", "b.php", "c.php")
	if len(found) != 0 || errs["a.php"] != nil {
		t.Errorf("safe: %v %v", found, errs)
	}
}
