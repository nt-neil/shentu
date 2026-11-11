package main

import (
	"slices"
	"testing"

	"github.com/nt-neil/shentu/tools"
)

// The hourly webshell check and the daily code audit report the same file once, with the audit's detail.
func TestReplaceOrAppend(t *testing.T) {
	all := []finding{{Key: "webshell:/w/s.php", Summary: "possible webshell: /w/s.php"}, {Key: "other"}}
	all = replaceOrAppend(all, []finding{{Key: "webshell:/w/s.php", Summary: "/w/s.php line 3: webshell"}, {Key: "code:secret:/a.js:2"}})
	all = replaceOrAppend(all, []finding{{Key: "code:secret:/a.js:2", Summary: "again"}})
	if len(all) != 3 || all[0].Summary != "/w/s.php line 3: webshell" || all[2].Summary != "again" {
		t.Errorf("got %+v", all)
	}
}

// Findings of info-tier rules and the summary of unfinished files are not pushed;
// alert-tier findings are, keyed by path, line and rule.
func TestCodeAuditFindings(t *testing.T) {
	audit := tools.CodeAudit{Findings: []tools.CodeFinding{
		{Kind: "injection", Severity: "critical", Path: "/a.php", Line: 3, Detail: "t", Fix: "f", Rule: "php-x-quiet", CWE: "CWE-89", Tier: "info"},
		{Kind: "injection", Severity: "warning", Path: "/a.php", Line: 3, Detail: "t", Fix: "f", Rule: "php-x-loud", CWE: "CWE-78", Tier: "alert"},
		{Kind: "injection", Severity: "info", Tier: "info", Detail: "2 file(s) were too large", Files: []tools.UnfinishedFile{{Path: "/b.php", Reason: "size"}}},
		{Kind: "injection", Severity: "critical", Path: "/e.php", Line: 1, Detail: "t", Fix: "f", Rule: "php-x-untiered"}, // no tier: not pushed
		{Kind: "secret", Severity: "warning", Path: "/k.js", Line: 2, Detail: "d", Fix: "f"},
		{Kind: "webshell", Severity: "critical", Path: "/w.php", Line: 1, Detail: "d", Fix: "f"},
		{Kind: "audit", Severity: "info", Detail: "the audit is unfinished: its time ran out"}, // pushed as a warning, after the findings
		{Kind: "audit", Severity: "info", Detail: "3 more finding(s) are not listed"},
	}}
	var keys []string
	for _, f := range codeAuditFindings(audit) {
		keys = append(keys, f.Key)
	}
	want := []string{"code:injection:/a.php:3:php-x-loud", "code:secret:/k.js:2", "webshell:/w.php", "code:audit:unfinished", "code:audit:truncated"}
	if !slices.Equal(keys, want) {
		t.Errorf("keys = %v, want %v", keys, want)
	}
}
