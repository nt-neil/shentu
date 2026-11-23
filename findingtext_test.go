package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/tools"
)

// The English summaries are the ones before v0.5.5, word for word: these
// are the format strings of patrol.go at 4ea1b29 (uid0 and webshell were
// the text plus the value).
func TestFindingTextEnglish(t *testing.T) {
	was := map[string]string{
		"f_ssh":           "%d failed SSH logins from %s in the last hour (successful logins: %d)%s",
		"f_ssh_text":      "; read from text logs, which anyone on this host can write to: check them before acting",
		"f_unparsed":      "%s line(s) %s are neither a key nor a comment; sshd ignores them, but check none is a key written in another form",
		"f_unparsed_more": " and %d more (%d in all)",
		"f_port":          "new listening port %s by %s (%s)",
		"f_proc":          "suspicious process pid %d (%s): %s",
		"f_keys":          "authorized_keys changed: %s (%d keys)",
		"f_keylink":       "%s links to %s, outside the home; sshd reads the keys there (%d keys), check who can write that file",
		"f_sharedkey":     "one SSH key (%s) is in the authorized_keys of %s; attackers plant one key in every account, check that it is yours",
		"f_preload":       "/etc/ld.so.preload loads %s into every program, a common rootkit trick; check each library with dpkg -S or rpm -qf and verify it with dpkg -V or rpm -V",
		"f_pam":           "PAM module %s was not installed by a package; a PAM backdoor can let anyone log in by SSH; check it with dpkg -S or rpm -qf %s",
		"f_cert":          "certificate for %s expires in %d days",
		"f_kev_os":        "%s %s has %s, which is being exploited in the wild (%s); update it: %v",
		"f_kev_app":       "%s pins %s %s, which has %s, exploited in the wild (%s); upgrade it",
	}
	for k, v := range was {
		if got := dt(false, k); got != v {
			t.Errorf("%s: %q, was %q", k, got, v)
		}
	}
	for k, was := range map[string]string{"f_uid0": "account with UID 0 besides root: ", "f_webshell": "possible webshell: "} {
		v := "%x 100% /a b"
		if got := newFinding("k", "critical", nil, k, v).Summary; got != was+v {
			t.Errorf("%s: %q, was %q", k, got, was+v)
		}
	}
	got, _ := sshFindings(map[string]any{"verified": false, "complete": true, "sources": []tools.SSHSource{{IP: "203.0.113.9", Failed: 5, Accepted: 1}}}, nil, 5, false)
	if len(got) != 1 || got[0].Summary != "5 failed SSH logins from 203.0.113.9 in the last hour (successful logins: 1); read from text logs, which anyone on this host can write to: check them before acting" {
		t.Errorf("ssh: %+v", got)
	}
	k := tools.KeyFile{Path: "/root/.ssh/authorized_keys", Unparsed: make([]int, unparsedLinesMax+2)}
	if f := unparsedKeysFinding(k); !strings.HasPrefix(f.Summary, "/root/.ssh/authorized_keys line(s) 0, 0,") || !strings.Contains(f.Summary, ", 0 and 2 more (22 in all) are neither a key nor a comment;") {
		t.Errorf("unparsed: %q", f.Summary)
	}
}

// With a Chinese setting the report says these findings in Chinese, the
// values as they came; English is left only in values and names.
func TestFindingTextChinese(t *testing.T) {
	fs := []finding{
		newFinding("p", "warning", nil, "f_port", "tcp:8080", "nc", "/usr/bin/nc"),
		newFinding("p", "critical", nil, "f_proc", 42, "deleted_exe", "/tmp/x -c"),
		newFinding("u", "critical", nil, "f_uid0", "toor"),
		newFinding("k", "warning", nil, "f_keys", "/root/.ssh/authorized_keys", 2),
		newFinding("k", "warning", nil, "f_keylink", "/home/a/.ssh/authorized_keys", "/srv/k", 1),
		newFinding("s", "warning", nil, "f_sharedkey", "SHA256:abc", "a, b"),
		newFinding("l", "critical", nil, "f_preload", "/lib/x.so"),
		newFinding("m", "warning", nil, "f_pam", "/lib/security/pam_x.so", "/lib/security/pam_x.so"),
		newFinding("w", "critical", nil, "f_webshell", "/var/www/a.php"),
		newFinding("c", "warning", nil, "f_cert", "example.com:443", 3),
		newFinding("v", "critical", nil, "f_kev_os", "openssl", "3.0.1", "CVE-2024-0001", "OpenSSL Bug", "apt-get install --only-upgrade openssl"),
		newFinding("v", "critical", nil, "f_kev_app", "/srv/app/package-lock.json", "lodash", "4.17.0", "CVE-2024-0002", "Lodash Bug"),
		unparsedKeysFinding(tools.KeyFile{Path: "/root/.ssh/authorized_keys", Unparsed: make([]int, unparsedLinesMax+2)}),
	}
	ssh, _ := sshFindings(map[string]any{"verified": false, "sources": []tools.SSHSource{{IP: "203.0.113.9", Failed: 5}}}, nil, 5, true)
	fs = append(fs, ssh...)
	var b strings.Builder
	for _, f := range fs {
		if f.zh == "" || f.said(true) != f.zh || f.said(false) != f.Summary {
			t.Errorf("%+v", f)
		}
		b.WriteString(f.said(true) + "\n")
	}
	// The values this test puts in (names, versions, a command) are taken
	// out whole; what is left must be Chinese.
	out := b.String()
	for _, v := range []string{"tcp:8080", "nc", "deleted_exe", "/tmp/x -c", "toor", "SHA256:abc", "a, b", "example.com:443",
		"openssl 3.0.1", "CVE-2024-0001", "CVE-2024-0002", "OpenSSL Bug", "Lodash Bug", "apt-get install --only-upgrade openssl",
		"lodash 4.17.0"} {
		out = strings.ReplaceAll(out, v, "")
	}
	if left := englishLeft(out); len(left) > 0 {
		t.Errorf("English left: %q in\n%s", left, b.String())
	}
}

// The Chinese summary is not saved (state.json, tool results, anything
// written and read back): a finding read back says its English summary in
// a Chinese report, never nothing, and no error.
func TestFindingReadBackFallsBack(t *testing.T) {
	f := newFinding("cert:example.com:443", "warning", nil, "f_cert", "example.com:443", 3)
	b, err := json.Marshal(f)
	if err != nil || strings.Contains(string(b), "憑證") {
		t.Fatalf("%s %v", b, err)
	}
	var back finding
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if got := back.said(true); got != f.Summary || got == "" {
		t.Errorf("read back: %q", got)
	}
	// The baseline (state.json) the next patrol compares with keeps the
	// risks' English summaries only.
	dir := t.TempDir()
	st := &state{Alerted: map[string]time.Time{f.Key: time.Now()}}
	st.Profile.Risks = []tools.Risk{{Key: "ssh_password", Severity: "warning", Summary: "SSH accepts passwords"}}
	if err := st.save(dir); err != nil {
		t.Fatal(err)
	}
	loaded := loadState(dir)
	r := loaded.Profile.Risks[0]
	if got := (finding{r.Key, r.Severity, r.Summary, nil, ""}).said(true); got != "SSH accepts passwords" {
		t.Errorf("risk read back: %q", got)
	}
}
