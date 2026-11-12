package hostenv

// SSH logins on Linux: the auth logs (rotated and gzipped ones too), or
// journald when there are none. Moved from tools/ssh.go (Phase 1c); the
// parsing rules against crafted user names are the tools ones.

import (
	"container/heap"
	"context"
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

var journalArgv = []string{"/usr/bin/journalctl", "-u", "ssh", "-u", "sshd", "--since", SlotTime, "-o", "short-iso", "--no-pager"}

// Streamed (no stdout cap applies); a day of a busy journal can take
// minutes to read, so it may run longer than MaxTimeout.
func init() { registerBig(journalArgv, 0, 15*time.Minute) }

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

// ScanAuthLogs streams the lines of the auth logs among logPaths
// (patterns naming "auth" or "secure", with their ".1"; .gz is unpacked
// on the fly) to fn, skipping files untouched since since; without any,
// journald's ssh and sshd units. Memory does not grow with the logs.
// source names what was read.
func (LinuxCollector) ScanAuthLogs(ctx context.Context, src Source, logPaths []string, since time.Time, fn func(line string)) (source string, err error) {
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
			// A file that fails half way (a line over MaxLineBytes) still
			// gave its earlier lines, as before; it is not counted as read.
			if err := ScanLines(src, f, fn); err == nil {
				used = append(used, f)
			}
		}
	}
	if len(used) > 0 {
		return strings.Join(used, ","), nil
	}
	argv := append([]string(nil), journalArgv...)
	argv[6] = since.UTC().Format("2006-01-02 15:04:05") + " UTC" // journalctl reads a bare time as local
	res, err := RunLines(ctx, src, argv, fn)
	if err == nil && res.ExitCode != 0 {
		err = &exitError{res.ExitCode}
	}
	if err != nil {
		return "none (no auth log readable and journalctl failed: " + err.Error() + ")", err
	}
	return "journald", nil
}

type exitError struct{ code int }

func (e *exitError) Error() string { return "exit status " + strconv.Itoa(e.code) }

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

// MaxTrackedSources bounds the sources an SSHLogins keeps while it
// counts, so memory stays flat on a log from a botnet. Up to this many
// distinct sources the counts are exact; past it, the least active source
// makes room for a new one (space-saving), and the busiest ones, the ones
// reported, keep their counts.
const MaxTrackedSources = 2048

// SSHLogins groups sshd's login events by source IP as lines stream in.
type SSHLogins struct {
	since, now time.Time
	onlyIP     string
	by         map[string]*sshAgg
	low        aggHeap // sources that never logged in, least active on top
	evicted    int
}

type sshAgg struct {
	SSHSource
	users map[string]map[string]bool // kind -> names (at most 20 each)
	slot  int                        // index in low, -1 once it logged in
}

// aggHeap is a min-heap of sources by activity, then by IP (the larger IP
// goes first), so eviction is O(log n) per line.
type aggHeap []*sshAgg

func (h aggHeap) Len() int { return len(h) }
func (h aggHeap) Less(i, j int) bool {
	if a, b := h[i].total(), h[j].total(); a != b {
		return a < b
	}
	return h[i].IP > h[j].IP
}
func (h aggHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].slot, h[j].slot = i, j
}
func (h *aggHeap) Push(x any) {
	a := x.(*sshAgg)
	a.slot = len(*h)
	*h = append(*h, a)
}
func (h *aggHeap) Pop() any {
	old := *h
	a := old[len(old)-1]
	*h = old[:len(old)-1]
	a.slot = -1
	return a
}

// NewSSHLogins starts a count of events since since (only onlyIP when set).
func NewSSHLogins(since, now time.Time, onlyIP string) *SSHLogins {
	return &SSHLogins{since: since, now: now, onlyIP: onlyIP, by: map[string]*sshAgg{}}
}

func (a *sshAgg) total() int { return a.Failed + a.InvalidUser + a.Accepted }

// Add counts one log line.
func (c *SSHLogins) Add(l string) {
	// Cheap tests first: most lines of a log are not sshd login events.
	if !strings.Contains(l, " sshd") || !(strings.Contains(l, "Failed ") || strings.Contains(l, "Invalid user ") || strings.Contains(l, "Accepted ")) {
		return
	}
	ts, ok := ParseLogTime(l, c.now)
	if !ok || ts.Before(c.since) {
		return
	}
	var ip, user, kind string
	if m := reFailed.FindStringSubmatch(l); m != nil {
		user, ip, kind = m[1], m[2], "failed"
	} else if m := reInvalid.FindStringSubmatch(l); m != nil {
		user, ip, kind = m[1], m[2], "invalid"
	} else if m := reAccepted.FindStringSubmatch(l); m != nil {
		user, ip, kind = m[2], m[3], "accepted"
	} else {
		return
	}
	if net.ParseIP(ip) == nil {
		return
	}
	if strings.Contains(user, " from ") || strings.Contains(user, ": ") {
		user = "[crafted user name]" // still an attempt from ip, but do not echo the bait
	}
	if len(user) > 64 {
		user = CutString(user, 64)
	}
	if c.onlyIP != "" && ip != c.onlyIP {
		return
	}
	s := c.by[ip]
	if s == nil {
		if len(c.by) >= MaxTrackedSources {
			c.evict()
		}
		s = &sshAgg{SSHSource: SSHSource{IP: ip, First: ts}, users: map[string]map[string]bool{"failed": {}, "invalid": {}, "accepted": {}}}
		c.by[ip] = s
		heap.Push(&c.low, s)
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
	if len(s.users[kind]) < 20 {
		s.users[kind][user] = true
	}
	if s.slot >= 0 {
		if s.Accepted > 0 {
			heap.Remove(&c.low, s.slot) // a source that got in is never dropped
		} else {
			heap.Fix(&c.low, s.slot)
		}
	}
}

// evict drops the least active source that never logged in (a source that
// got in is never dropped: it is the one that matters most).
func (c *SSHLogins) evict() {
	if c.low.Len() == 0 {
		return
	}
	victim := heap.Pop(&c.low).(*sshAgg)
	delete(c.by, victim.IP)
	c.evicted++
}

// Evicted is how many sources were dropped to stay within the bound.
func (c *SSHLogins) Evicted() int { return c.evicted }

// Result is the 50 busiest sources (failed + invalid), ties by IP.
func (c *SSHLogins) Result() []SSHSource {
	list := make([]SSHSource, 0, len(c.by))
	for _, s := range c.by {
		names := func(kind string) []string {
			var l []string
			for u := range s.users[kind] {
				l = append(l, u)
			}
			sort.Strings(l)
			return l
		}
		out := s.SSHSource
		out.FailedUsers, out.InvalidUsers, out.AcceptedUsers = names("failed"), names("invalid"), names("accepted")
		list = append(list, out)
	}
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
	agg := NewSSHLogins(since, at, "")
	source, err := c.ScanAuthLogs(ctx, src, logPaths, since, agg.Add)
	ev := AuthEvents{WindowHours: 24, FailedBySrc: map[string]int{}}
	for _, s := range agg.Result() {
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
	detail := "from " + source
	if n := agg.Evicted(); n > 0 {
		detail += "; " + strconv.Itoa(n) + " low-activity sources not tracked (more than " + strconv.Itoa(MaxTrackedSources) + " sources)"
	}
	return Obs[AuthEvents]{Status: StatusOK, Detail: detail, Value: ev}
}
