package engine

import (
	"slices"
	"testing"
)

// An application's own path guard: a function that returns false unless the
// path it is given resolves (realpath) under a base directory, and true only
// after that check (Welcart's usces_is_reserved_file). A caller that reads the
// file only when the guard says true, or stops when it says false, reads no
// path the request chose. On the code audit's path.
func TestGuardFunctions(t *testing.T) {
	e := engineForTest(t)
	const welcart = "function is_reserved_file($file_path, $dir = 0) {\n" +
		"    $real_file_path = realpath($file_path);\n" +
		"    $real_base_path = realpath(WP_CONTENT_DIR . '/uploads/logs') . DIRECTORY_SEPARATOR;\n" +
		"    if (false === $real_file_path || 0 !== strpos($real_file_path, $real_base_path)) {\n" +
		"        return false;\n" +
		"    }\n" +
		"    $reserved_file = array('progress.txt', 'log.txt');\n" +
		"    $path_parts = pathinfo($file_path);\n" +
		"    if (in_array($path_parts['basename'], $reserved_file, true)) {\n" +
		"        $res = true;\n" +
		"    } else {\n" +
		"        $res = false;\n" +
		"    }\n" +
		"    return $res;\n" +
		"}\n"
	const prefix = "function in_logs($p) {\n" +
		"    $real = realpath($p);\n" +
		"    if ($real === false || strpos($real, '/var/logs/') !== 0) {\n" +
		"        return false;\n" +
		"    }\n" +
		"    return true;\n" +
		"}\n"
	read := "$f = $_POST['f'];\n"
	all := func(line string) []string {
		return []string{line + ":php-deserialization-phar-wrapper", line + ":php-path-traversal-file-read", line + ":php-ssrf-http-request"}
	}
	for _, c := range []struct {
		name, src string
		want      []string
	}{
		{"Welcart's guard, read inside the true branch (no finding)",
			welcart + read + "if (is_reserved_file($f)) {\n    echo file_get_contents($f);\n}\n", nil},
		{"Welcart's guard, stop when false (no finding)",
			welcart + read + "if (!is_reserved_file($f)) {\n    die('no');\n}\n$t = file_get_contents($f);\n", nil},
		{"a realpath prefix guard returning true (no finding)",
			prefix + read + "if (!in_logs($f)) {\n    return;\n}\n$t = file_get_contents($f);\n", nil},
		{"the guard in another class (no finding)",
			"class Files {\n    static " + prefix + "}\n" + read + "if (Files::in_logs($f)) {\n    $t = file_get_contents($f);\n}\n", nil},
		{"no guard (control)",
			read + "$t = file_get_contents($f);\n", all("3")},
		{"a guard that only checks the file exists",
			"function ok($p) {\n    if (!file_exists($p)) {\n        return false;\n    }\n    return true;\n}\n" + read + "if (ok($f)) {\n    $t = file_get_contents($f);\n}\n", append(all("10"), "3:php-deserialization-phar-wrapper")},
		{"a guard that checks only the base name: ../ and URLs pass it",
			"function ok($p) {\n    if (!in_array(basename($p), array('log.txt'), true)) {\n        return false;\n    }\n    return true;\n}\n" + read + "if (ok($f)) {\n    $t = file_get_contents($f);\n}\n", all("10")},
		{"a guard that replaces its own copy of the path",
			"function ok($p) {\n    $p = '/var/logs/log.txt';\n    return true;\n}\n" + read + "if (ok($f)) {\n    $t = file_get_contents($f);\n}\n", all("8")},
		{"a guard with a path that returns true before the check",
			"function ok($p, $force) {\n    if ($force) {\n        return true;\n    }\n    $real = realpath($p);\n    if ($real === false || strpos($real, '/var/logs/') !== 0) {\n        return false;\n    }\n    return true;\n}\n" + read + "if (ok($f, 1)) {\n    $t = file_get_contents($f);\n}\n", all("14")},
		{"a lookup of basename($p) leaves the path open: ../../x/log.txt passes it",
			read + "if (in_array(basename($f), array('log.txt'), true)) {\n    $t = file_get_contents($f);\n}\n", all("4")},
		{"a lookup of strtolower($o) (no finding)",
			"$o = $_GET['o'];\nif (in_array(strtolower($o), array('asc', 'desc'), true)) {\n    mysqli_query($c, \"SELECT * FROM t ORDER BY id $o\");\n}\n", nil},
		{"a lookup of intval($id) leaves the value open: 1 OR 1 passes it",
			"$id = $_GET['id'];\nif (in_array(intval($id), array(1, 2), true)) {\n    mysqli_query($c, \"SELECT * FROM t WHERE id = $id\");\n}\n", []string{"4:php-sqli-string-concat"}},
		{"where realpath() failed the path is still anything",
			read + "$real = realpath($f);\nif ($real === false) {\n    $t = file_get_contents($f);\n}\n", all("5")},
		{"where realpath() found it, a URL or wrapper is not the path (path rules still report)",
			read + "$real = realpath($f);\nif ($real !== false) {\n    $t = file_get_contents($f);\n}\n", []string{"5:php-path-traversal-file-read"}},
		{"the guard's result not used",
			prefix + read + "in_logs($f);\n$t = file_get_contents($f);\n", all("11")},
	} {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{"a.php": "<?php\n" + c.src}
			src := []byte(files["a.php"])
			pr := e.NewProject([]string{"a.php"}, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{})
			own, _, _ := e.ScanTimed("php", "a.php", src)
			part, _ := pr.ScanCallsPart("a.php", src, nil)
			var got []string
			for _, f := range append(own, part.Found...) {
				got = append(got, itoa(f.Line)+":"+f.RuleID)
			}
			slices.Sort(got)
			got = slices.Compact(got)
			if !slices.Equal(got, c.want) {
				t.Errorf("reported %v, want %v", got, c.want)
			}
		})
	}
}
