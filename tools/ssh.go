package tools

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var sshLogins = Tool{
	Name:        "ssh_logins",
	Description: "SSH login attempts grouped by source IP: failed passwords, invalid users and successful logins. Use it to spot brute force and to check whether an attacking IP ever got in.",
	Params: schema(`{"type":"object","properties":{
		"since_hours":{"type":"number","description":"look back this many hours (default 24)"},
		"ip":{"type":"string","description":"only this source IP"}}}`),
	Run: func(ctx context.Context, env *Env, args json.RawMessage) (any, error) {
		var a struct {
			SinceHours float64 `json:"since_hours"`
			IP         string  `json:"ip"`
		}
		if err := decode(args, &a); err != nil {
			return nil, err
		}
		return SSHSummary(ctx, env, hoursAgo(a.SinceHours, 24), a.IP)
	},
}

// SSHSource is the per-IP summary.
type SSHSource struct {
	IP          string    `json:"ip"`
	Failed      int       `json:"failed"`
	InvalidUser int       `json:"invalid_user"`
	Accepted    int       `json:"accepted"`
	Users       []string  `json:"users"`
	First       time.Time `json:"first"`
	Last        time.Time `json:"last"`
}

var (
	// User names are attacker-controlled and may contain "from <ip> port"; the greedy
	// user group and the anchored sshd suffix make the IP the one sshd wrote last.
	// The prefix is "<RFC3339 time> host sshd[pid]: " or "Mon dd hh:mm:ss host sshd[pid]: "
	// (OpenSSH 9.8+ logs as sshd-session), so injected text cannot start a second message.
	sshdPrefix = `^(?:\S+|\w{3} +\d+ \d\d:\d\d:\d\d) \S+ sshd(?:-session)?\[\d+\]: `
	reFailed   = regexp.MustCompile(sshdPrefix + `Failed (?:password|publickey|keyboard-interactive/pam|none) for (?:invalid user )?(.*) from (\S+) port \d+(?: ssh2)?(?: \[preauth\])?\s*$`)
	reInvalid  = regexp.MustCompile(sshdPrefix + `Invalid user (.*) from (\S+) port \d+(?: \[preauth\])?\s*$`)
	reAccepted = regexp.MustCompile(sshdPrefix + `Accepted (\S+) for (\S+) from (\S+) port \d+ ssh2(?:: .*)?$`)
)

// SSHSummary reads auth logs (or journald when there are none) and groups events by IP.
func SSHSummary(ctx context.Context, env *Env, since time.Time, onlyIP string) (map[string]any, error) {
	lines, source := authLines(ctx, env, since)
	by := map[string]*SSHSource{}
	users := map[string]map[string]bool{}
	for _, l := range lines {
		ts, ok := parseLogTime(l)
		if !ok || ts.Before(since) {
			continue
		}
		var ip, user, kind string
		if m := reFailed.FindStringSubmatch(l); m != nil {
			user, ip, kind = m[1], m[2], "failed"
		} else if m := reInvalid.FindStringSubmatch(l); m != nil {
			user, ip, kind = m[1], m[2], "invalid"
		} else if m := reAccepted.FindStringSubmatch(l); m != nil {
			user, ip, kind = m[2], m[3], "accepted"
		} else {
			continue
		}
		if net.ParseIP(ip) == nil {
			continue
		}
		if strings.Contains(user, " from ") || strings.Contains(user, ": ") {
			user = "[crafted user name]" // still an attempt from ip, but do not echo the bait
		}
		if len(user) > 64 {
			user = Cut(user, 64)
		}
		if onlyIP != "" && ip != onlyIP {
			continue
		}
		s := by[ip]
		if s == nil {
			s = &SSHSource{IP: ip, First: ts}
			by[ip] = s
			users[ip] = map[string]bool{}
		}
		switch kind {
		case "failed":
			s.Failed++
		case "invalid":
			s.InvalidUser++
		case "accepted":
			s.Accepted++
		}
		if ts.Before(s.First) {
			s.First = ts
		}
		if ts.After(s.Last) {
			s.Last = ts
		}
		if len(users[ip]) < 20 {
			users[ip][user] = true
		}
	}
	list := make([]SSHSource, 0, len(by))
	for ip, s := range by {
		for u := range users[ip] {
			s.Users = append(s.Users, u)
		}
		sort.Strings(s.Users)
		list = append(list, *s)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].Failed+list[i].InvalidUser > list[j].Failed+list[j].InvalidUser
	})
	if len(list) > 50 {
		list = list[:50]
	}
	return map[string]any{"source": source, "since": since, "sources": list}, nil
}

// authLines returns log lines from the configured auth logs, falling back to journald.
func authLines(ctx context.Context, env *Env, since time.Time) ([]string, string) {
	var lines []string
	var used []string
	for _, pattern := range env.LogPaths {
		if !strings.Contains(pattern, "auth") && !strings.Contains(pattern, "secure") {
			continue
		}
		matches, _ := filepath.Glob(pattern)
		rotated, _ := filepath.Glob(pattern + ".1")
		for _, f := range append(rotated, matches...) {
			st, err := os.Stat(f)
			if err != nil || st.ModTime().Before(since) {
				continue
			}
			if ls, err := readLines(f); err == nil {
				lines = append(lines, ls...)
				used = append(used, f)
			}
		}
	}
	if len(used) > 0 {
		return lines, strings.Join(used, ",")
	}
	out, err := exec.CommandContext(ctx, "journalctl", "-u", "ssh", "-u", "sshd",
		"--since", since.Format("2006-01-02 15:04:05"), "-o", "short-iso", "--no-pager").Output()
	if err != nil {
		return nil, "none (no auth log readable and journalctl failed: " + err.Error() + ")"
	}
	return strings.Split(string(out), "\n"), "journald"
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		r = gz
	}
	var lines []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

// parseLogTime understands RFC3339 (rsyslog default on Ubuntu 24.04, journalctl short-iso)
// and the classic "Nov  5 18:50:01" syslog format.
func parseLogTime(line string) (time.Time, bool) {
	if i := strings.IndexByte(line, ' '); i > 0 {
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05-0700"} {
			if t, err := time.Parse(layout, line[:i]); err == nil {
				return t, true
			}
		}
	}
	if len(line) >= 15 {
		t, err := time.ParseInLocation("Jan _2 15:04:05", line[:15], time.Local)
		if err == nil {
			now := time.Now()
			t = t.AddDate(now.Year(), 0, 0)
			if t.After(now.Add(24 * time.Hour)) {
				t = t.AddDate(-1, 0, 0)
			}
			return t, true
		}
	}
	return time.Time{}, false
}
