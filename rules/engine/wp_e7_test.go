package engine

import "testing"

// WordPress code E7 found reported once the REST handlers in nested arrays
// were followed: a fixed host kept through set_url_scheme(), array_diff()'s
// result made of its first argument only. Each case is checked against the
// way around that is still input, and a REST upload's client file name is.
func TestWordPressE7Cases(t *testing.T) {
	e := engineForTest(t)
	for _, c := range []struct {
		name, rule, src string
		want            bool
	}{
		{"set_url_scheme keeps a fixed host", "php-ssrf-http-request",
			"<?php\n$u = 'http://api.wordpress.org/patterns/1.0/?q=' . $_GET['q'];\nif (wp_http_supports(array('ssl'))) {\n\t$u = set_url_scheme($u, 'https');\n}\nwp_remote_get($u);\n", false},
		{"set_url_scheme of an input URL", "php-ssrf-http-request",
			"<?php\n$u = set_url_scheme($_GET['u'], 'https');\nwp_remote_get($u);\n", true},
		{"array_diff takes its first argument's values", "php-sqli-string-concat",
			"<?php\n$old = $wpdb->get_col('SELECT id FROM t');\n$gone = array_diff($old, $_GET['ids']);\n$wpdb->query(\"DELETE FROM t WHERE id IN ('\" . implode(\"','\", $gone) . \"')\");\n", false},
		{"array_diff of the input", "php-sqli-string-concat",
			"<?php\n$old = $wpdb->get_col('SELECT id FROM t');\n$new = array_diff($_GET['ids'], $old);\n$wpdb->query(\"DELETE FROM t WHERE id IN ('\" . implode(\"','\", $new) . \"')\");\n", true},
		// The client's file name is the request's: phar:// in it reaches file_exists. (Its tmp_name, the
		// path PHP wrote, is still reported too: the engine cannot clear one key of the array; a known issue.)
		{"a REST upload's client file name", "php-deserialization-phar-wrapper",
			"<?php\nadd_action('rest_api_init', function () {\n\tregister_rest_route('m/v1', '/f', array(array('methods' => 'POST', 'callback' => 'm_f', 'permission_callback' => '__return_true')));\n});\n" +
				"function m_f($request) {\n\t$files = $request->get_file_params();\n\treturn file_exists($files['file']['name']);\n}\n", true},
	} {
		fs, err := e.Scan("php", "a.php", []byte(c.src))
		got := false
		for _, f := range fs {
			if f.RuleID == c.rule {
				got = true
			}
		}
		if err != nil || got != c.want {
			t.Errorf("%s: %s reported %v (err %v), want %v", c.name, c.rule, got, err, c.want)
		}
	}
}
