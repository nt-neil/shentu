package engine

// Cases for the PHP lane's format and matching needs (p1-classes): source
// arguments, array keys, literals behind class members, literal length and
// exclusions, inner keys of a source, call sources by name, prefix checks on
// paths that were never resolved, flags taken out with "~", and PHP 8 match.

import (
	"strings"
	"testing"
)

func TestPHPLaneNeeds(t *testing.T) {
	sec := strings.Join([]string{"made", "up", "test", "value"}, "-") // no credential-like value in the file
	r20run(t, []r20case{
		// 1. a source only with a given argument (Joomla filters), any case
		{"N1a path filter", "php", "php-path-traversal-file-read", "<?php\nreadfile(JPATH_ROOT . '/x/' . $this->input->get('f', '', 'Path'));\n", true},
		{"N1b int filter", "php", "php-path-traversal-file-read", "<?php\nreadfile(JPATH_ROOT . '/x/' . $this->input->get('f', '', 'int'));\n", false},
		{"N1c filter from a variable", "php", "php-path-traversal-file-read", "<?php\nreadfile(JPATH_ROOT . '/x/' . $this->input->get('f', '', $filter));\n", false},
		// 2. array keys only
		{"N2a key from request", "php", "php-sqli-orderby-identifier", "<?php\n$q->orderBy(array($_GET['s'] => SORT_ASC));\n", true},
		{"N2b value from request", "php", "php-sqli-orderby-identifier", "<?php\n$q->orderBy(['id' => $_GET['d'], 'name' => SORT_ASC]);\n", false},
		{"N2c not an array", "php", "php-sqli-orderby-identifier", "<?php\n$q->orderBy($_GET['s']);\n", true},
		{"N2d list item", "php", "php-sqli-orderby-identifier", "<?php\n$q->orderBy([$_GET['s']]);\n", true},
		// 3. literals behind class members and derived values, with a depth bound
		{"N3a static property", "php", "php-hardcoded-secret", "<?php\nclass T {\n  private static $k = '" + sec + "';\n  function f($c) { return JWT::encode($c, self::$k, 'HS256'); }\n}\n", true},
		{"N3b concatenated", "php", "php-hardcoded-secret", "<?php\n$k = '" + sec + "' . 'x';\n$t = JWT::encode($c, $k, 'HS256');\n", true},
		{"N3c two classes, two values", "php", "php-hardcoded-secret", "<?php\nclass A { const KEY = '" + sec + "'; }\nclass B { const KEY = ''; function f($c) { return JWT::encode($c, self::KEY, 'HS256'); } }\n", false},
		{"N3d within the depth bound", "php", "php-hardcoded-secret", "<?php\n$a = '" + sec + "';\n$b = $a;\n$c = $b;\n$t = JWT::encode($x, $c, 'HS256');\n", true},
		{"N3e past the depth bound", "php", "php-hardcoded-secret", "<?php\n$a = '" + sec + "';\n$b = $a;\n$c = $b;\n$d = $c;\n$e = $d;\n$t = JWT::encode($x, $e, 'HS256');\n", false},
		{"N3f call that reads configuration", "php", "php-hardcoded-secret", "<?php\n$k = getenv('JWT_KEY');\n$t = JWT::encode($x, $k, 'HS256');\n", false},
		// 4. min_len and exclude
		{"N4a short key", "php", "php-hardcoded-secret", "<?php\n$s = hash_hmac('sha256', $d, 'abc');\n", false},
		{"N4b label", "php", "php-hardcoded-secret", "<?php\n$s = hash_hmac('sha256', $d, 'app-sha256');\n", false},
		// 5. inner keys of a source
		{"N5a tmp_name", "php", "php-file-upload", "<?php\nmove_uploaded_file($_FILES['f']['tmp_name'], $dir . '/' . $_FILES['f']['tmp_name']);\n", false},
		{"N5b name of a multiple upload", "php", "php-file-upload", "<?php\nmove_uploaded_file($_FILES['f']['tmp_name'][$i], $dir . '/' . $_FILES['f']['name'][$i]);\n", true},
		{"N5c type through a variable", "php", "php-file-upload", "<?php\n$u = $_FILES['f'];\nmove_uploaded_file($u['tmp_name'], $dir . '/x.' . $u['type']);\n", true},
		// 6. a call source matches the function only
		{"N6a request helper", "php", "php-sqli-orderby-identifier", "<?php\n$rows = DB::table('t')->orderBy(\\request('sort'))->get();\n", true},
		{"N6b request method", "php", "php-sqli-orderby-identifier", "<?php\n$rows = DB::table('t')->orderBy($client?->request('sort'))->get();\n", false},
		// 8. a prefix check needs a resolved path
		{"N8a strncmp on the joined path", "php", "php-path-traversal-file-read", "<?php\n$b = __DIR__ . '/files/';\n$p = $b . $_GET['f'];\nif (strncmp($p, $b, strlen($b)) === 0) { readfile($p); }\n", true},
		{"N8b strncmp on realpath", "php", "php-path-traversal-file-read", "<?php\n$b = __DIR__ . '/files/';\n$p = realpath($b . $_GET['f']);\nif (strncmp($p, $b, strlen($b)) === 0) { readfile($p); }\n", false},
		{"N8c realpath inline", "php", "php-path-traversal-file-read", "<?php\n$p = __DIR__ . '/files/' . $_GET['f'];\nif (str_starts_with(realpath($p), __DIR__ . '/files/')) { readfile(realpath($p)); }\n", false},
		{"N8d reassigned after realpath", "php", "php-path-traversal-file-read", "<?php\n$p = realpath(__DIR__ . '/files/' . $_GET['f']);\n$p = __DIR__ . '/files/' . $_GET['f'];\nif (str_starts_with($p, __DIR__ . '/files/')) { readfile($p); }\n", true},
		// 9. flags taken out with "~"
		{"N9a and-not", "php", "php-xxe", "<?php\nsimplexml_load_string($x, 'SimpleXMLElement', LIBXML_NONET & ~LIBXML_NOENT);\n", false},
		{"N9b still set", "php", "php-xxe", "<?php\nsimplexml_load_string($x, 'SimpleXMLElement', LIBXML_NOENT & ~LIBXML_NONET);\n", true},
		// 11. match with fixed arms
		{"N11a fixed arms", "php", "php-path-traversal-file-read", "<?php\nreadfile(__DIR__ . '/' . match ($_GET['t']) { 'a', 'b' => 'a.txt', default => 'c.txt' });\n", false},
		{"N11b subject in an arm", "php", "php-path-traversal-file-read", "<?php\nreturn readfile(__DIR__ . '/' . match (true) { $ok => 'a.txt', default => $_GET['t'] });\n", true},
	})
}
