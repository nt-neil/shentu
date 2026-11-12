package tools

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSSHSummary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Linux host test: Linux auth log files")
	}
	dir := t.TempDir()
	now := time.Now()
	iso := now.UTC().Format("2006-01-02T15:04:05.000000-07:00")
	classic := now.Format("Jan _2 15:04:05")
	old := now.Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	log := strings.Join([]string{
		iso + " vm sshd[1]: Failed password for invalid user admin from 203.0.113.7 port 4000 ssh2",
		iso + " vm sshd[2]: Failed password for root from 203.0.113.7 port 4001 ssh2",
		classic + " vm sshd[3]: Invalid user test from 198.51.100.9 port 22",
		iso + " vm sshd[4]: Accepted publickey for ops from 192.0.2.10 port 5000 ssh2: ED25519 SHA256:x",
		old + " vm sshd[5]: Failed password for root from 203.0.113.99 port 1 ssh2",
		iso + " vm CRON[6]: pam_unix(cron:session): session opened",
		iso + " vm sshd[7]: Invalid user x from 192.0.2.10 port 1 from 203.0.113.50 port 2222",
		iso + " vm sshd[9]: Invalid user z: Accepted password for root from 198.51.100.200 port 22 ssh2 from 203.0.113.51 port 3",
		iso + " vm sshd-session[10]: Accepted publickey for deploy from 192.0.2.20 port 6000 ssh2: ED25519-CERT SHA256:abc ID deploy@ci (serial 7) CA ED25519 SHA256:def",
		iso + " vm sshd[8]: Failed password for invalid user y from 192.0.2.10 port 1 from 203.0.113.50 port 2223 ssh2",
	}, "\n")
	p := filepath.Join(dir, "auth.log")
	os.WriteFile(p, []byte(log), 0o600)
	r, err := SSHSummary(context.Background(), &Env{LogPaths: []string{p}}, now.Add(-24*time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]SSHSource{}
	for _, s := range r["sources"].([]SSHSource) {
		got[s.IP] = s
	}
	if s := got["203.0.113.7"]; s.Failed != 2 || len(s.FailedUsers)+len(s.InvalidUsers) != 2 {
		t.Errorf("203.0.113.7 = %+v", s)
	}
	if s := got["192.0.2.10"]; len(s.AcceptedUsers) != 1 || s.AcceptedUsers[0] != "ops" || len(s.InvalidUsers)+len(s.FailedUsers) != 0 {
		t.Errorf("accepted and attempted users must be listed apart: %+v", s)
	}
	if s := got["198.51.100.9"]; len(s.AcceptedUsers) != 0 || len(s.InvalidUsers) != 1 {
		t.Errorf("an invalid user must not show up as accepted: %+v", s)
	}
	if s := got["198.51.100.9"]; s.InvalidUser != 1 {
		t.Errorf("198.51.100.9 = %+v", s)
	}
	if s := got["192.0.2.20"]; s.Accepted != 1 {
		t.Errorf("certificate login missed: %+v", s)
	}
	if s := got["192.0.2.10"]; s.Accepted != 1 {
		t.Errorf("192.0.2.10 = %+v", s)
	}
	if s := got["203.0.113.50"]; s.InvalidUser != 1 || s.Failed != 1 {
		t.Errorf("spoofed user name attributed wrongly: %+v / %+v", s, got["192.0.2.10"])
	}
	if s, ok := got["198.51.100.200"]; ok {
		t.Errorf("injected Accepted event was counted: %+v", s)
	}
	if s := got["192.0.2.10"]; s.Failed != 0 || s.InvalidUser != 0 {
		t.Errorf("IP inside a user name was counted: %+v", s)
	}
	if _, ok := got["203.0.113.99"]; ok {
		t.Error("event older than since was counted")
	}
}

func TestBlockGuards(t *testing.T) {
	for _, bad := range []string{"127.0.0.1", "0.0.0.0", "::", "::1", "10.0.0.0/8", "not-an-ip", "224.0.0.1", "169.254.1.1"} {
		if _, err := blockIP.Preview(json.RawMessage(`{"ip":"` + bad + `","reason":"x"}`)); err == nil {
			t.Errorf("block_ip accepted %q", bad)
		}
	}
	prev, err := blockIP.Preview(json.RawMessage(`{"ip":"203.0.113.7","ttl":"9999h","reason":"x"}`))
	if err != nil || !strings.Contains(prev, "timeout 2592000s") {
		t.Errorf("ttl not capped: %q %v", prev, err)
	}
}

func TestLogPathAllowlist(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Linux host test: Linux /var/log paths")
	}
	pats := []string{"/var/log/auth.log", "/var/log/nginx/*.log"}
	for p, want := range map[string]bool{
		"/var/log/auth.log": true, "/var/log/auth.log.1": true, "/var/log/nginx/access.log": true,
		"/etc/shadow": false, "/var/log/../../etc/shadow": false, "/var/log/nginx/../../../etc/passwd": false,
	} {
		if allowedLog(p, pats) != want {
			t.Errorf("allowedLog(%q) != %v", p, want)
		}
	}
}

func TestWebshellPatterns(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "x.php"), []byte(`<?php @eval($_POST['c']); ?>`), 0o644)
	os.WriteFile(filepath.Join(dir, "ok.php"), []byte(`<?php echo "hello"; ?>`), 0o644)
	r, err := FileChanges(context.Background(), []string{dir}, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	files := r["files"].([]Changed)
	if len(files) != 2 || len(files[0].Webshell) == 0 || !strings.HasSuffix(files[0].Path, "x.php") || len(files[1].Webshell) != 0 {
		t.Errorf("unexpected result: %+v", files)
	}
}

func TestCut(t *testing.T) {
	if got := Cut("封鎖這個位址", 4); got != "封…" {
		t.Errorf("Cut split a character: %q", got)
	}
	if got := Cut("abc", 5); got != "abc" {
		t.Errorf("Cut changed a short string: %q", got)
	}
}

func TestHexToIPv6(t *testing.T) {
	if got := net.ParseIP(hexToIPv6("fe800000000000000000000000000001")); !got.Equal(net.ParseIP("fe80::1")) {
		t.Errorf("hexToIPv6 = %v", got)
	}
}

func TestMinerSigns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Linux host test: Linux /proc executable paths")
	}
	cases := []struct {
		exe, cmd string
		want     bool
	}{
		{"/tmp/.x/kswapd0", "kswapd0 -o stratum+tcp://pool.example:3333 -u wallet", true},
		{"/dev/shm/sys", "sys --donate-level 1 -o 198.51.100.7:443", true},
		{"/usr/local/bin/xmrig", "xmrig", true},
		{"/opt/m/run (deleted)", "run -a rx/0 --url 198.51.100.7:80", true},
		{"/usr/bin/grep", "grep -r stratum+tcp:// /var/log", false},
		{"/usr/bin/sed", "sed -n /--donate-level/p notes", false},
		{"/tmp/grep", "grep -o stratum+tcp://pool.example:3333", true},
		{"/usr/bin/grep (deleted)", "grep --donate-level 1", true},
		{"/tmp/xmrig (deleted)", "kworker", true},
		{"/usr/local/bin/dataminer-report", "dataminer-report --daily", false},
		{"/usr/bin/python3", "python3 manage.py runserver", false},
		{"/usr/bin/ffmpeg", "ffmpeg -i in.mp4 -a rx/0.mp4", false},
	}
	for _, c := range cases {
		if got := minerSigns(c.exe, c.cmd); got != c.want {
			t.Errorf("%s %q: got %v, want %v", c.exe, c.cmd, got, c.want)
		}
	}
}
