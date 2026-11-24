package engine

import (
	"slices"
	"testing"
)

// filter_input(INPUT_GET, ...) and an application's filterInput(INPUT_POST,
// ...) wrapper (YesWiki's SecurityController) read the request: a source of
// every PHP rule reading $_GET, $_POST or $_COOKIE, for the INPUT_* it reads.
// A number or bool filter leaves no input, and FILTER_SANITIZE_SPECIAL_CHARS
// cleans where htmlspecialchars() does. On the code audit's path.
func TestFilterInputSources(t *testing.T) {
	e := engineForTest(t)
	for _, c := range []struct {
		name, src string
		want      []string
	}{
		{"filter_input(INPUT_GET) to a redirect", "<?php\nheader('Location: ' . filter_input(INPUT_GET, 'u', FILTER_SANITIZE_URL));\n",
			[]string{"2:php-open-redirect-redirect"}},
		{"a filterInput(INPUT_POST) method, then a redirect", "<?php\n$u = $this->securityController->filterInput(INPUT_POST, 'incomingurl', FILTER_SANITIZE_URL, false, 'string');\nheader('Location: ' . $u);\n",
			[]string{"3:php-open-redirect-redirect"}},
		{"\\INPUT_GET, any case of the name", "<?php\n$id = FILTER_INPUT(\\INPUT_GET, 'id');\nmysqli_query($c, \"SELECT * FROM t WHERE id = $id\");\n",
			[]string{"3:php-sqli-string-concat"}},
		{"INPUT_COOKIE", "<?php\nsystem('ls ' . filter_input(INPUT_COOKIE, 'd'));\n",
			[]string{"2:php-cmdi-shell-exec"}},
		{"FILTER_SANITIZE_SPECIAL_CHARS is still input for SQL", "<?php\n$q = filter_input(INPUT_GET, 'q', FILTER_SANITIZE_SPECIAL_CHARS);\nmysqli_query($c, \"SELECT * FROM t WHERE n = '$q'\");\n",
			[]string{"3:php-sqli-string-concat"}},
		{"FILTER_VALIDATE_INT (no finding)", "<?php\n$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);\nmysqli_query($c, \"SELECT * FROM t WHERE id = $id\");\n", nil},
		{"a bool filter on a method (no finding)", "<?php\n$r = $this->sec->filterInput(INPUT_POST, 'r', FILTER_VALIDATE_BOOL, false, 'bool');\nheader('Location: ' . $r);\n", nil},
		{"FILTER_SANITIZE_SPECIAL_CHARS between tags (no finding)", "<?php\necho '<p>' . filter_input(INPUT_GET, 'q', FILTER_SANITIZE_SPECIAL_CHARS) . '</p>';\n", nil},
		{"INPUT_SERVER (no finding)", "<?php\nheader('Location: ' . filter_input(INPUT_SERVER, 'HTTP_REFERER'));\n", nil},
		{"a filterInput of something else (no finding)", "<?php\nheader('Location: ' . $form->filterInput('u'));\n", nil},
		{"FILTER_VALIDATE_URL is still input for a server-side request", "<?php\n$u = filter_input(INPUT_GET, 'u', FILTER_VALIDATE_URL);\n$ch = curl_init($u);\n",
			[]string{"3:php-ssrf-http-request"}},
		{"YesWiki's LoginAction: FILTER_SANITIZE_URL, then the app's Redirect", "<?php\nclass LoginAction {\n    function run() {\n        $incomingurl = $this->securityController->filterInput(INPUT_POST, 'incomingurl', FILTER_SANITIZE_URL, false, 'string');\n        header('Location: ' . $incomingurl);\n    }\n}\n",
			[]string{"5:php-open-redirect-redirect"}},
		{"a filterInput whose first argument is a variable (no finding)", "<?php\nheader('Location: ' . $x->filterInput($a, 'k'));\n", nil},
		{"a filterInput whose first argument is another constant (no finding)", "<?php\nheader('Location: ' . $x->filterInput(MY_FIELDS, 'k'));\n", nil},
		{"FILTER_VALIDATE_INT | FILTER_NULL_ON_FAILURE is another ID, raw in PHP 7", "<?php\n$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT | FILTER_NULL_ON_FAILURE);\nmysqli_query($c, \"SELECT * FROM t WHERE id = $id\");\n",
			[]string{"3:php-sqli-string-concat"}},
		{"FILTER_VALIDATE_INT | FILTER_FLAG_ENCODE_LOW is FILTER_VALIDATE_URL", "<?php\n$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT | FILTER_FLAG_ENCODE_LOW);\nmysqli_query($c, \"SELECT * FROM t WHERE id = $id\");\n",
			[]string{"3:php-sqli-string-concat"}},
		{"FILTER_VALIDATE_INT with flags in the options argument (no finding)", "<?php\n$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE);\nmysqli_query($c, \"SELECT * FROM t WHERE id = $id\");\n", nil},
		{"a named filter: FILTER_VALIDATE_INT (no finding)", "<?php\n$id = filter_input(INPUT_GET, 'id', filter: FILTER_VALIDATE_INT);\nmysqli_query($c, \"SELECT * FROM t WHERE id = $id\");\n", nil},
		{"every argument named, filter: \\FILTER_VALIDATE_INT (no finding)", "<?php\n$id = filter_input(type: INPUT_GET, var_name: 'id', filter: \\FILTER_VALIDATE_INT);\nmysqli_query($c, \"SELECT * FROM t WHERE id = $id\");\n", nil},
		{"FILTER_UNSAFE_RAW | FILTER_FLAG_STRIP_LOW is still input", "<?php\n$id = filter_input(INPUT_GET, 'id', FILTER_UNSAFE_RAW | FILTER_FLAG_STRIP_LOW);\nmysqli_query($c, \"SELECT * FROM t WHERE id = $id\");\n",
			[]string{"3:php-sqli-string-concat"}},
		{"a named options: third is still input", "<?php\n$id = filter_input(INPUT_GET, 'id', options: FILTER_VALIDATE_INT);\nmysqli_query($c, \"SELECT * FROM t WHERE id = $id\");\n",
			[]string{"3:php-sqli-string-concat"}},
		{"$_GET (control)", "<?php\nheader('Location: ' . $_GET['u']);\n", []string{"2:php-open-redirect-redirect"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{"a.php": c.src}
			pr := e.NewProject([]string{"a.php"}, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{})
			src := []byte(c.src)
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

// source_args name constants (INPUT_POST) only in PHP. In JS a name is a
// variable whose value is unrelated to it, so req.get(host) is not the Host
// header, while req.get('host') is.
func TestSourceArgConstantsPHPOnly(t *testing.T) {
	e := engineForTest(t)
	express := "const express = require('express');\nconst app = express();\napp.get('/x', async (req, res) => {\n"
	next := "import { headers } from 'next/headers';\nimport { redirect } from 'next/navigation';\nexport default function Page() {\n"
	for _, c := range []struct {
		name, path, src string
		want            []string
	}{
		{"a variable named host (no host-header finding)", "a.js", express + "  const host = pickHeaderName();\n  await fetch('http://' + req.get(host) + '/x');\n});\n", nil},
		{"a variable HOST holding another header (no host-header finding)", "a.js", express + "  const HOST = 'x-real-ip';\n  await fetch('http://' + req.get(HOST) + '/x');\n});\n", nil},
		{"Next headers().get(host) (no finding)", "app/page.js", next + "  const host = 'x-target';\n  redirect('https://' + headers().get(host) + '/a');\n}\n", nil},
		{"req.get('host') (control)", "a.js", express + "  await fetch('http://' + req.get('host') + '/x');\n});\n", []string{"4:js-ssrf-host-header"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{c.path: c.src}
			pr := e.NewProject([]string{c.path}, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{})
			src := []byte(c.src)
			own, _, _ := e.ScanTimed(LangOf(c.path), c.path, src)
			part, _ := pr.ScanCallsPart(c.path, src, nil)
			var got []string
			for _, f := range append(own, part.Found...) {
				if f.RuleID == "js-ssrf-host-header" || f.RuleID == "js-open-redirect-next" {
					got = append(got, itoa(f.Line)+":"+f.RuleID)
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
