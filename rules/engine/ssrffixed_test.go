package engine

import "testing"

// A server-side request is the input's to aim only when it picks the scheme or
// the host. A fixed start that holds scheme://host/, or that no input can turn
// into a scheme (a local path, a drive, a constant followed by a path segment:
// usc-e-shop 2.9.6 classes/paymentWelcart.class.php:7207, fopen(WP_CONTENT_DIR .
// '/uploads/' . $file_name)), leaves it neither. The path rule still reports.
func TestSSRFFixedStart(t *testing.T) {
	e := engineForTest(t)
	const ssrf, read = "php-ssrf-http-request", "php-path-traversal-file-read"
	for _, c := range []struct {
		name, start string
		ssrf        bool
	}{
		{"scheme://host/", "'https://api.example.com/v1/' . ", false},
		{"a local path", "'/var/data/' . ", false},
		{"a constant then a path segment (Welcart)", "WP_CONTENT_DIR . '/uploads/' . ", false},
		{"a variable holding a constant and a path segment (Welcart)", "$base . ", false},
		{"a drive", "'C:\\\\data\\\\' . ", false},
		{"a path from the root", "'/uploads/' . ", false},
		{"no start (control)", "", true},
		{"scheme, host from the input", "'http://' . ", true},
		{"an empty start", "'' . ", true},
		{"a host without /: @evil.com/ moves it", "'https://api.example.com' . ", true},
		{"http, completed by ://evil", "'http' . ", true},
		{"http:, completed by //evil", "'http:' . ", true},
		{"file://", "'file://' . ", true},
		{"php://", "'php://' . ", true},
		{"a constant then a bare /: K = 'http:/' gives http://", "WP_CONTENT_DIR . '/' . ", true},
		{"a constant then /a: K = 'http:/' gives http://a, which the input extends", "WP_CONTENT_DIR . '/a' . ", true},
		{"a bare /: //evil.com", "'/' . ", true},
		{"a backslash: \\\\evil\\share", "'\\\\\\\\' . ", true},
		{"a drive letter alone", "'C:' . ", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := "<?php\n$base = WP_CONTENT_DIR . '/uploads/';\n$x = $_GET['x'];\n$t = file_get_contents(" + c.start + "$x);\n"
			own, _, _ := e.ScanTimed("php", "a.php", []byte(src))
			var gotS, gotR bool
			for _, f := range own {
				gotS = gotS || f.RuleID == ssrf && f.Line == 4
				gotR = gotR || f.RuleID == read && f.Line == 4
			}
			if gotS != c.ssrf || !gotR {
				t.Errorf("%s: ssrf %v (want %v), file read %v (want true)", src, gotS, c.ssrf, gotR)
			}
		})
	}
}
