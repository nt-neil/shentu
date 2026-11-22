package engine

import "testing"

// Gaps found while measuring c3, fixed apart from it (#185 follow-up).

// A closure is analysed with the input it is called with (here by a function
// calling its parameter, c1); its return is the closure's value, not the
// enclosing function's result (yeswiki 4.6.5 includes/i18n.inc.php:
// detectPreferedLanguage, once closures handed to builtins are followed).
func TestClosureReturnNotFunctionResult(t *testing.T) {
	e := engineForTest(t)
	const tap = "function tap($v, $cb) {\n    $cb($v);\n}\n"
	for _, c := range []struct {
		name, src string
		want      bool
	}{
		{"a closure's return", "<?php\n" + tap + "function lang() {\n    tap($_GET['q'], function ($m) {\n        return $m;\n    });\n    return 'fr';\n}\ninclude 'lang/' . lang() . '.php';\n", false},
		{"input returned (control)", "<?php\n" + tap + "function lang() {\n    tap($_GET['q'], function ($m) {\n        return 'x';\n    });\n    return $_GET['q'];\n}\ninclude 'lang/' . lang() . '.php';\n", true},
	} {
		f, _, err := e.ScanTimed("php", "a.php", []byte(c.src))
		if err != nil {
			t.Fatal(err)
		}
		got := false
		for _, x := range f {
			got = got || x.RuleID == "php-path-traversal-file-include"
		}
		if got != c.want {
			t.Errorf("%s: reported %v, want %v", c.name, got, c.want)
		}
	}
}

// wp_create_nonce() and wp_hash() return hex digits: what they are given does
// not reach the result (wp-admin/includes/plugin.php activate_plugin, which
// redirects with the nonce of the plugin's name).
func TestHexFuncsClean(t *testing.T) {
	e := engineForTest(t)
	for _, c := range []struct {
		name, src string
		want      bool
	}{
		{"wp_create_nonce", "<?php\n$p = $_GET['plugin'];\nwp_redirect(wp_create_nonce('activate_' . $p));\n", false},
		{"wp_hash", "<?php\nwp_redirect(wp_hash($_GET['p']));\n", false},
		{"no hash (control)", "<?php\n$p = $_GET['plugin'];\nwp_redirect($p);\n", true},
		{"md5 is not one (control)", "<?php\nwp_redirect(md5($_GET['p'], true));\n", true},
	} {
		f, _, err := e.ScanTimed("php", "a.php", []byte(c.src))
		if err != nil {
			t.Fatal(err)
		}
		got := false
		for _, x := range f {
			got = got || x.RuleID == "php-open-redirect-redirect"
		}
		if got != c.want {
			t.Errorf("%s: reported %v, want %v", c.name, got, c.want)
		}
	}
}

// A sink in another file is reached after a nonce check as a sink in the file
// is: the request is the site's own (wp-admin/users.php, under
// check_admin_referer, redirecting to the referer it was given).
func TestNonceBeforeCalleeSink(t *testing.T) {
	e := engineForTest(t)
	b := "<?php\nfunction go_to($u) {\n    header(\"Location: $u\");\n}\n"
	for _, c := range []struct {
		name, a string
		want    bool
	}{
		{"nonce, then a callee's sink", "<?php\nrequire 'b.php';\n$r = $_REQUEST['ref'];\ncheck_admin_referer('bulk-users');\ngo_to($r);\n", false},
		{"no nonce (control)", "<?php\nrequire 'b.php';\n$r = $_REQUEST['ref'];\ngo_to($r);\n", true},
		{"nonce in another branch (control)", "<?php\nrequire 'b.php';\n$r = $_REQUEST['ref'];\nif ($z) { check_admin_referer('bulk-users'); }\ngo_to($r);\n", true},
	} {
		files := map[string]string{"a.php": c.a, "b.php": b}
		pr := e.NewProject([]string{"a.php", "b.php"}, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{})
		got := false
		for _, f := range auditPath(t, e, pr, "a.php", []byte(c.a)) {
			got = got || f.RuleID == "php-open-redirect-redirect"
		}
		if got != c.want {
			t.Errorf("%s: reported %v, want %v", c.name, got, c.want)
		}
	}
}

// A callee's sink that needs input at the start (header("Location: $u")) is
// not reached by an argument that starts with a fixed text, as the sink written
// out is not (wp-admin/network/sites.php: add_query_arg($_POST,
// network_admin_url('sites.php')) given to wp_redirect()).
func TestFixedStartIntoCallee(t *testing.T) {
	e := engineForTest(t)
	b := "<?php\nfunction go_to($u) {\n    header(\"Location: $u\");\n}"
	for _, c := range []struct {
		name, a string
		want    bool
	}{
		{"a fixed address, then input", "<?php\nrequire 'b.php';\n$l = admin_url('x.php') . '?a=' . $_GET['a'];\ngo_to($l);\n", false},
		{"query arguments on a fixed address", "<?php\nrequire 'b.php';\ngo_to(add_query_arg($_POST, network_admin_url('sites.php')));\n", false},
		{"input at the start (control)", "<?php\nrequire 'b.php';\ngo_to($_GET['a']);\n", true},
		{"input, then a fixed text (control)", "<?php\nrequire 'b.php';\ngo_to($_GET['a'] . '/x');\n", true},
	} {
		files := map[string]string{"a.php": c.a, "b.php": b}
		pr := e.NewProject([]string{"a.php", "b.php"}, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{})
		got := false
		for _, f := range auditPath(t, e, pr, "a.php", []byte(c.a)) {
			got = got || f.RuleID == "php-open-redirect-redirect"
		}
		if got != c.want {
			t.Errorf("%s: reported %v, want %v", c.name, got, c.want)
		}
	}
}
