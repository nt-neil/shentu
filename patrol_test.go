package main

import "testing"

// The hourly webshell check and the daily code audit report the same file once, with the audit's detail.
func TestReplaceOrAppend(t *testing.T) {
	all := []finding{{Key: "webshell:/w/s.php", Summary: "possible webshell: /w/s.php"}, {Key: "other"}}
	all = replaceOrAppend(all, finding{Key: "webshell:/w/s.php", Summary: "/w/s.php line 3: webshell"})
	all = replaceOrAppend(all, finding{Key: "code:secret:/a.js:2"})
	if len(all) != 3 || all[0].Summary != "/w/s.php line 3: webshell" {
		t.Errorf("got %+v", all)
	}
}
