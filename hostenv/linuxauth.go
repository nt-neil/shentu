package hostenv

// SSH logins on Linux: the auth logs (rotated and gzipped ones too), or
// journald when there are none. Moved from tools/ssh.go (Phase 1c); the
// parsing rules against crafted user names are the tools ones.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DefaultLogPaths are the log files Shentu reads unless configured
// otherwise (config.go [tools] log_paths).
var DefaultLogPaths = []string{"/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/nginx/*.log", "/var/log/apache2/*.log"}

// MaxLogBytes caps one log file read: a brute force can fill auth.log, and
// the checks must see it whole.
const MaxLogBytes = 512 << 20

var journalArgv = []string{"/usr/bin/journalctl", "-u", "ssh", "-u", "sshd", "--since", SlotTime, "-o", "short-iso", "--no-pager"}

func init() { registerBig(journalArgv, 256<<20, MaxTimeout) }

// SSHSource is the per-IP summary of SSH login attempts.
type SSHSource struct {
	IP          string `json:"ip"`
	Failed      int    `json:"failed"`
	InvalidUser int    `json:"invalid_user"`
	Accepted    int    `json:"accepted"`
	// Kept apart so a model cannot mistake an attempted name for a login that worked.
	FailedUsers   []string  `json:"failed_users,omitempty"`   // existing accounts, wrong credentials
	InvalidUsers  []string  `json:"invalid_users,omitempty"`  // names that do not exist here
	AcceptedUsers []string  `json:"accepted_users,omitempty"` // logged in successfully
	First         time.Time `json:"first"`
	Last          time.Time `json:"last"`
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

// AuthLogLines returns the lines of the auth logs among logPaths (patterns
// naming "auth" or "secure", with their ".1"), skipping files untouched
// since since; without any, journald's ssh and sshd units. source names
// what was read.
func (c LinuxCollector) AuthLogLines(ctx context.Context, src Source, logPaths []string, since time.Time) (lines []string, source string) {
	lines, source, _ = c.authLogLines(ctx, src, logPaths, since)
	return lines, source
}

func (LinuxCollector) authLogLines(ctx context.Context, src Source, logPaths []string, since time.Time) (lines []string, source string, err error) {
	var used []string
	for _, pattern := range logPaths {
		if !strings.Contains(pattern, "auth") && !strings.Contains(pattern, "secure") {
			continue
		}
		for _, f := range append(Glob(src, pattern+".1"), Glob(src, pattern)...) {
			st, err := Stat(src, f)
			if err != nil || st.ModTime.Before(since) {
				continue
			}
			if ls, err := ReadLogLines(src, f); err == nil {
				lines = append(lines, ls...)
				used = append(used, f)
			}
		}
	}
	if len(used) > 0 {
		return lines, strings.Join(used, ","), nil
	}
	argv := append([]string(nil), journalArgv...)
	argv[6] = since.Format("2006-01-02 15:04:05")
	res, err := src.Run(ctx, argv)
	if err == nil && res.ExitCode != 0 {
		err = &exitError{res.ExitCode}
	}
	if err != nil {
		return nil, "none (no auth log readable and journalctl failed: " + err.Error() + ")", err
	}
	return strings.Split(string(res.Stdout), "\n"), "journald", nil
}

type exitError struct{ code int }

func (e *exitError) Error() string { return "exit status " + strconv.Itoa(e.code) }

// ReadLogLines reads a log file (gunzipping a .gz) into lines. A line over
// 1 MiB fails the read, as bufio.Scanner does.
func ReadLogLines(src Source, path string) ([]string, error) {
	b, err := ReadFileMax(src, path, MaxLogBytes)
	if err != nil {
		return nil, err
	}
	var r io.Reader = bytes.NewReader(b)
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		r = io.LimitReader(gz, MaxLogBytes)
	}
	var lines []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

// ParseLogTime understands RFC3339 (rsyslog default on Ubuntu 24.04,
// journalctl short-iso) and the classic "Nov  5 18:50:01" syslog format,
// which has no year: it is this year, or last year if that would be more
// than a day ahead of now.
func ParseLogTime(line string, now time.Time) (time.Time, bool) {
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
			t = t.AddDate(now.Year(), 0, 0)
			if t.After(now.Add(24 * time.Hour)) {
				t = t.AddDate(-1, 0, 0)
			}
			return t, true
		}
	}
	return time.Time{}, false
}

// SSHLogins groups sshd's login events since since by source IP (only
// onlyIP when set): the 50 busiest sources, at most 20 names of each kind.
func SSHLogins(lines []string, since, now time.Time, onlyIP string) []SSHSource {
	by := map[string]*SSHSource{}
	users := map[string]map[string]map[string]bool{} // ip -> kind -> user
	for _, l := range lines {
		ts, ok := ParseLogTime(l, now)
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
			user = CutString(user, 64)
		}
		if onlyIP != "" && ip != onlyIP {
			continue
		}
		s := by[ip]
		if s == nil {
			s = &SSHSource{IP: ip, First: ts}
			by[ip] = s
			users[ip] = map[string]map[string]bool{"failed": {}, "invalid": {}, "accepted": {}}
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
		if len(users[ip][kind]) < 20 {
			users[ip][kind][user] = true
		}
	}
	list := make([]SSHSource, 0, len(by))
	for ip, s := range by {
		names := func(kind string) []string {
			var l []string
			for u := range users[ip][kind] {
				l = append(l, u)
			}
			sort.Strings(l)
			return l
		}
		s.FailedUsers, s.InvalidUsers, s.AcceptedUsers = names("failed"), names("invalid"), names("accepted")
		list = append(list, *s)
	}
	// Busiest first; ties by IP so the list does not change between runs.
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i].Failed+list[i].InvalidUser, list[j].Failed+list[j].InvalidUser
		if a != b {
			return a > b
		}
		return list[i].IP < list[j].IP
	})
	if len(list) > 50 {
		list = list[:50]
	}
	return list
}

// AuthEvents is the auth_events fact: failed SSH logins per source over
// the last day before the snapshot.
func (c LinuxCollector) AuthEvents(ctx context.Context, src Source, at time.Time, logPaths []string) Obs[AuthEvents] {
	if logPaths == nil {
		logPaths = DefaultLogPaths
	}
	since := at.Add(-24 * time.Hour)
	lines, source, err := c.authLogLines(ctx, src, logPaths, since)
	ev := AuthEvents{WindowHours: 24, FailedBySrc: map[string]int{}}
	for _, s := range SSHLogins(lines, since, at, "") {
		if n := s.Failed + s.InvalidUser; n > 0 {
			ev.FailedBySrc[s.IP] = n
		}
	}
	if err != nil {
		r := Classify(err)
		if _, ok := err.(*exitError); ok {
			r = ReasonCommandFailed
		}
		return Obs[AuthEvents]{Status: StatusUnknown, Reason: r, Detail: source, Value: ev}
	}
	return Obs[AuthEvents]{Status: StatusOK, Detail: "from " + source, Value: ev}
}
