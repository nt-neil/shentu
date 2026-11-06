package main

import (
	"strings"
	"testing"
)

func TestMask(t *testing.T) {
	in := `{"line":"password=hunter2 token: abcdef123 AKIAABCDEFGHIJKLMNOP sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaa 123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`
	out := mask(in)
	for _, secret := range []string{"hunter2", "abcdef123", "AKIAABCDEFGHIJKLMNOP", "sk-ant-api03", "123456789:AAAA"} {
		if strings.Contains(out, secret) {
			t.Errorf("not masked: %s in %s", secret, out)
		}
	}
	if !strings.HasSuffix(out, `"}`) {
		t.Errorf("JSON structure damaged: %s", out)
	}
	key := "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
	if mask(key) != "[REDACTED PRIVATE KEY]" {
		t.Errorf("private key not masked")
	}
	more := "Authorization: Bearer abcdefgh12345678 github_pat_11AAAAAAAAAAAAAAAAAAAAAA " +
		"AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA https://user:s3cretpw@example.com/x " +
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEtruncated"
	out = mask(more)
	for _, secret := range []string{"abcdefgh12345678", "github_pat_11", "AIzaSy", "s3cretpw", "MIIEtruncated"} {
		if strings.Contains(out, secret) {
			t.Errorf("not masked: %s in %s", secret, out)
		}
	}
	if !strings.Contains(out, "https://[REDACTED]@example.com/x") {
		t.Errorf("URL damaged: %s", out)
	}
}

func TestTextToolCalls(t *testing.T) {
	skills := map[string]skill{"ssh-bruteforce": {Name: "ssh-bruteforce"}}
	cases := map[string]string{
		`{"name": "ssh_logins", "arguments": {"since_hours": 1}}`:       "ssh_logins",
		"```json\n{\"name\":\"listening_ports\",\"arguments\":{}}\n```": "listening_ports",
		`<tool_call>{"name":"processes","parameters":{}}</tool_call>`:   "processes",
		`{"name": "ssh_bruteforce", "arguments": {}}`:                   "use_skill",
		`{"name": "rm_rf", "arguments": {}}`:                            "",
		`There were 15 failed logins.`:                                  "",
	}
	for in, want := range cases {
		calls := textToolCalls(in, skills)
		got := ""
		if len(calls) == 1 {
			got = calls[0].Function.Name
		}
		if got != want {
			t.Errorf("textToolCalls(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSkillsLoad(t *testing.T) {
	s := loadSkills(t.TempDir())
	for _, n := range []string{"triage", "daily-patrol", "ssh-bruteforce", "vuln-patrol", "suspicious-process", "incident-report"} {
		if s[n].Body == "" || s[n].Description == "" {
			t.Errorf("skill %s missing or empty", n)
		}
	}
}

func TestPrintable(t *testing.T) {
	if got := printable("block 1.2.3.4\r\x1b[2Kharmless\u202e\n"); strings.ContainsAny(got, "\r\n\x1b\u202e") {
		t.Errorf("control characters left: %q", got)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for h, want := range map[string]bool{"localhost": true, "LOCALHOST": true, "127.0.0.1": true, "127.1.2.3": true, "::1": true, "0.0.0.0": true, "": true, "203.0.113.1": false} {
		if isLoopbackHost(h) != want {
			t.Errorf("isLoopbackHost(%q) != %v", h, want)
		}
	}
}
