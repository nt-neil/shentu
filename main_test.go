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
	if got := printable("block 1.2.3.4\r\x1b[2Kharmless\n"); strings.ContainsAny(got, "\r\n\x1b") {
		t.Errorf("control characters left: %q", got)
	}
}
