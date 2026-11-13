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

// A linked authorized_keys file warns even when every line parses.
func TestKeyFileSymlinkNoUnparsed(t *testing.T) {
	got := keyFileFindings([]tools.KeyFile{
		{Path: "/home/a/.ssh/authorized_keys", Keys: 1, SymlinkOutsideHome: "/srv/shared/keys"},
		{Path: "/home/b/.ssh/authorized_keys", Keys: 2},
	})
	if len(got) != 1 || got[0].Key != "authorized_keys_symlink:/home/a/.ssh/authorized_keys" || got[0].Severity != "warning" {
		t.Fatalf("got %+v", got)
	}
	got = keyFileFindings([]tools.KeyFile{{Path: "/home/c/.ssh/authorized_keys", Keys: 1, SymlinkOutsideHome: "/srv/k", Unparsed: []int{3}}})
	if len(got) != 2 || got[1].Key != "authorized_key_unparsed:/home/c/.ssh/authorized_keys" {
		t.Fatalf("got %+v", got)
	}
}

// N-D1: a vulnerability check that failed or covered part goes into the
// daily report's unchecked section.
func TestUncheckedVulns(t *testing.T) {
	if s := uncheckedVulns("installed packages", nil, fmt.Errorf("OSV query failed")); !strings.Contains(s, "Not checked for vulnerabilities: installed packages") || !strings.Contains(s, "OSV query failed") {
		t.Errorf("failed: %q", s)
	}
	if s := uncheckedVulns("installed packages", map[string]any{"partial": "not checked: extras topic gone"}, nil); !strings.Contains(s, "partly checked") || !strings.Contains(s, "extras topic gone") {
		t.Errorf("partial: %q", s)
	}
	// N-R2, S-R1: KEV unavailable, a lock file that failed, ecosystems not queried.
	r := map[string]any{"total_vulns": 3, "kev": "CISA KEV list unavailable: timeout", "files": []tools.AppResult{{Path: "/srv/app/package-lock.json", Error: "OSV query failed"}},
		"ecosystems_not_queried": []string{"SUSE:Linux Enterprise Desktop 15 SP6 (no such OSV ecosystem; its modules are queried)"}}
	s := uncheckedVulns("application dependencies", r, nil)
	for _, want := range []string{"CISA KEV list", "package-lock.json", "OSV query failed", "Linux Enterprise Desktop"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in %q", want, s)
		}
	}
	if s := uncheckedVulns("installed packages", map[string]any{"kev": "none of these vulnerabilities is on the CISA KEV list"}, nil); s != "" {
		t.Errorf("KEV checked: %q", s)
	}
	if s := uncheckedVulns("installed packages", map[string]any{"total_vulns": 0}, nil); s != "" {
		t.Errorf("checked: %q", s)
	}
}

// N-A: the unchecked section stays short: lines cut at 200 bytes, at most 10
// lock files named, the same error once. S-A: no KEV line with nothing found.
// N-C: KEV lookups that could not be made are said.
func TestUncheckedVulnsBounded(t *testing.T) {
	var files []tools.AppResult
	for i := 0; i < 25; i++ {
		files = append(files, tools.AppResult{Path: fmt.Sprintf("/srv/app%02d/package-lock.json", i), Error: "OSV query failed: " + strings.Repeat("x", 500)})
	}
	files = append(files, tools.AppResult{Path: "/srv/other/go.sum", Error: "parse error"})
	s := uncheckedVulns("application dependencies", map[string]any{"files": files}, nil)
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		if len(l) > maxUncheckedLine+8 {
			t.Errorf("line of %d bytes", len(l))
		}
	}
	if strings.Count(s, "OSV query failed") != 1 || strings.Count(s, "package-lock.json") > uncheckedFiles {
		t.Errorf("not merged or not capped:\n%s", s)
	}
	if strings.Contains(s, "app15") {
		t.Errorf("more than 10 files named")
	}
	if s := uncheckedVulns("installed packages", map[string]any{"total_vulns": 0, "kev": "CISA KEV list unavailable: timeout"}, nil); s != "" {
		t.Errorf("KEV line with no vulnerability: %q", s)
	}
	if s := uncheckedVulns("installed packages", map[string]any{"total_vulns": 9, "kev_unchecked": 4}, nil); !strings.Contains(s, "4 vulnerabilities not checked against the CISA KEV list") {
		t.Errorf("KEV unchecked: %q", s)
	}
}

// Distinct errors are merged as shown (cut), and at most 10 error lines
// are listed; the rest are counted.
func TestUncheckedVulnsErrorLines(t *testing.T) {
	var files []tools.AppResult
	for i := 0; i < 12; i++ {
		files = append(files, tools.AppResult{Path: fmt.Sprintf("/srv/a%02d/go.sum", i), Error: fmt.Sprintf("error %02d", i)})
	}
	// Two errors that differ only past the cut are one line.
	long := strings.Repeat("y", 100)
	files = append(files, tools.AppResult{Path: "/srv/x/go.sum", Error: long + "1"}, tools.AppResult{Path: "/srv/z/go.sum", Error: long + "2"})
	s := uncheckedVulns("application dependencies", map[string]any{"files": files}, nil)
	if n := strings.Count(s, "- not checked ("); n != 10 || !strings.Contains(s, "and 4 more lock files not checked") {
		t.Errorf("%d error lines:\n%s", n, s)
	}
	s = uncheckedVulns("application dependencies", map[string]any{"files": files[12:]}, nil)
	if strings.Count(s, "- not checked (") != 1 {
		t.Errorf("errors equal once cut not merged:\n%s", s)
	}
}
