package main

import (
	"fmt"
	"slices"
	"strings"
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

// A patrol report lists at most patrolListMax findings, the most severe first
// (N11: 2000 findings went whole into the prompt and ~150 Telegram messages).
func TestMostSevere(t *testing.T) {
	var fs []finding
	for i := range 2000 {
		sev := "warning"
		if i%100 == 7 {
			sev = "critical"
		}
		fs = append(fs, finding{Key: fmt.Sprint(i), Severity: sev})
	}
	got := mostSevere(fs, patrolListMax)
	if len(got) != patrolListMax || got[0].Key != "7" || got[19].Key != "1907" || got[20].Severity != "warning" || got[20].Key != "0" {
		t.Errorf("got %d, first %+v, 20th %+v", len(got), got[0], got[20])
	}
	if few := mostSevere(fs[:3], patrolListMax); len(few) != 3 {
		t.Error("a short list is cut")
	}
}

// A check that could not tell (sshd_config unreadable when not run as root)
// is listed at the end of every report, apart from the findings, and is not
// a finding itself (pushed or held back by the cooldown).
func TestUncheckedSection(t *testing.T) {
	risks := []tools.Risk{
		{Key: "ssh:unreadable", Severity: "info", Summary: "cannot tell the SSH settings (PasswordAuthentication, PermitRootLogin): /etc/ssh/sshd_config.d (permission denied) could not be read; run Shentu as root, as sshd reads them"},
		{Key: "firewall:none", Severity: "info", Summary: "no host firewall detected"},
		{Key: "ssh:password", Severity: "warning", Summary: "SSH accepts passwords"},
	}
	s := uncheckedSection(risks)
	if !strings.Contains(s, "Not checked") || !strings.Contains(s, "sshd_config.d (permission denied)") ||
		strings.Contains(s, "firewall") || strings.Contains(s, "accepts passwords") {
		t.Errorf("section %q", s)
	}
	if uncheckedSection(risks[1:]) != "" {
		t.Error("a section with nothing unchecked")
	}
	if c := uncheckedConfigs([]string{"/etc/nginx/sites-enabled/a (symlink to /tmp/a, outside /etc)"}); !strings.Contains(c, "not read") || !strings.Contains(c, "outside /etc") {
		t.Errorf("configs %q", c)
	}
	if uncheckedConfigs(nil) != "" {
		t.Error("a section with every configuration read")
	}
}

// Round 2 (N2-1): a web root whose ACL could not be read is listed under
// "Not checked" and never pushed as an alert.
func TestWebrootACLUnknownNotPushed(t *testing.T) {
	audit := tools.CodeAudit{Findings: []tools.CodeFinding{{Kind: "webroot_acl_unknown", Severity: "info", Path: `C:\inetpub\wwwroot`,
		Detail: "cannot tell webroot ACL: access denied"}}, NotChecked: []string{`C:\inetpub\wwwroot: cannot tell webroot ACL: access denied`}}
	if f := codeAuditFindings(audit); len(f) != 0 {
		t.Errorf("pushed: %+v", f)
	}
	if s := notCheckedSection(audit.NotChecked); !strings.Contains(s, "Not checked by the code audit") || !strings.Contains(s, "cannot tell webroot ACL") {
		t.Errorf("section: %q", s)
	}
	if notCheckedSection(nil) != "" {
		t.Error("nothing to list, no section")
	}
}
