package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Credential-shaped test values are put together at run time, so none is kept
// in the source.
var (
	fakeAWSKey       = strings.Join([]string{"AKIA", "ABCDEFGHIJKLMNOP"}, "")
	fakeAnthropicKey = strings.Join([]string{"sk-ant", "api03", strings.Repeat("a", 24)}, "-")
	fakeBotToken     = strings.Join([]string{"123456789", strings.Repeat("A", 35)}, ":")
	fakeGitHubPAT    = strings.Join([]string{"github", "pat", "11" + strings.Repeat("A", 22)}, "_")
	fakeGoogleKey    = "AI" + "zaSy" + strings.Repeat("A", 33)
)

// pem is a PEM boundary line of a private key: pem("BEGIN", "RSA").
func pem(edge, kind string) string {
	return "-----" + edge + " " + kind + " PRIVATE" + " KEY-----"
}

func TestMask(t *testing.T) {
	in := `{"line":"password=hunter2 token: abcdef123 ` + fakeAWSKey + " " + fakeAnthropicKey + " " + fakeBotToken + `"}`
	out := mask(in)
	for _, secret := range []string{"hunter2", "abcdef123", fakeAWSKey, fakeAnthropicKey[:12], fakeBotToken[:14]} {
		if strings.Contains(out, secret) {
			t.Errorf("not masked: %s in %s", secret, out)
		}
	}
	if !strings.HasSuffix(out, `"}`) {
		t.Errorf("JSON structure damaged: %s", out)
	}
	key := pem("BEGIN", "OPENSSH") + "\nabc\n" + pem("END", "OPENSSH")
	if mask(key) != "[REDACTED PRIVATE KEY]" {
		t.Errorf("private key not masked")
	}
	more := "Authorization: Bearer abcdefgh12345678 " + fakeGitHubPAT + " " +
		fakeGoogleKey + " https://user:s3cretpw@example.com/x " +
		pem("BEGIN", "RSA") + "\nMIIEtruncated"
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

func TestAnswerOnceRetriesEmpty(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ready"}}]}`))
	}))
	defer srv.Close()
	a := &agent{llm: &llmClient{baseURL: srv.URL, http: srv.Client()}, log: newAuditLog(t.TempDir())}
	got, _, err := a.answerOnce(context.Background(), "  ", nil)
	if err != nil || got != "ready" || calls != 1 {
		t.Errorf("answerOnce = %q, %v after %d calls", got, err, calls)
	}
	if got, _, _ := a.answerOnce(context.Background(), "done", nil); got != "done" || calls != 1 {
		t.Errorf("answerOnce asked again for a non-empty answer")
	}
}

// help, --help and -h print the usage to stdout and exit 0, without a config;
// an unknown command prints it to stderr and exits 2.
func TestHelpExitCode(t *testing.T) {
	if cmd := os.Getenv("SHENTU_TEST_MAIN"); cmd != "" {
		os.Args = []string{"shentu", cmd}
		main()
		return
	}
	for cmd, want := range map[string]int{"help": 0, "--help": 0, "-h": 0, "frobnicate": 2} {
		c := exec.Command(os.Args[0], "-test.run=^TestHelpExitCode$")
		c.Env = append(os.Environ(), "SHENTU_TEST_MAIN="+cmd, "SHENTU_CONFIG="+filepath.Join(t.TempDir(), "none.toml"))
		var stdout, stderr bytes.Buffer
		c.Stdout, c.Stderr = &stdout, &stderr
		err := c.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		out, other := stdout.String(), stderr.String()
		if want != 0 {
			out, other = other, out
		}
		if code != want || !strings.Contains(out, "Usage:") || strings.Contains(other, "Usage:") {
			t.Errorf("%s: exit %d (want %d), stdout %q, stderr %q", cmd, code, want, stdout.String(), stderr.String())
		}
	}
}
