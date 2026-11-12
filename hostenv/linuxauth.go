package hostenv

// SSH logins on Linux: the auth logs (rotated and gzipped ones too), or
// journald when there are none. Moved from tools/ssh.go (Phase 1c); the
// parsing rules against crafted user names are the tools ones.

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"io/fs"
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

// journalBinArgv is the same at /bin, where some systems keep it without
// the /usr merge.
var journalBinArgv = append([]string{"/bin/journalctl"}, journalArgv[1:]...)

// JournalTimeout caps the journald read (streamed, no stdout cap). A
// journal that takes longer falls back to the text logs, marked
// unverified. The runner allows at most the value set here at start-up.
var JournalTimeout = 60 * time.Second

func init() {
	registerBig(journalArgv, 0, JournalTimeout)
	registerBig(journalBinArgv, 0, JournalTimeout)
}

// reSSHDLine is a line sshd wrote: the only lines that can count.
var reSSHDLine = regexp.MustCompile(sshdPrefix)

// unverifiedText says why text logs are not trusted like journald.
const unverifiedText = "text logs do not record the sender; local users can forge sshd lines"

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
	// Uncertainty is set only when more sources were seen than are tracked:
	// the events this source may have had before it was tracked (its counts
	// are a lower bound; counts plus Uncertainty an upper one).
	Uncertainty int `json:"count_uncertainty,omitempty"`
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

// ScanAuthLogs streams the sshd lines of the last day to a consumer that
// sink hands out, unmasked (fn masks whatever it outputs); memory does not
// grow with the logs. Each source tried gets a fresh consumer from sink,
// and the events are those of the last consumer handed out.
//
// journald comes first: its ssh and sshd units are filtered on
// _SYSTEMD_UNIT, which journald fills in itself, so verified is true. The
// text logs among logPaths (patterns naming "auth" or "secure", with their
// ".1"; .gz unpacked on the fly; files untouched since since skipped) are
// read when journald is missing, fails, times out (JournalTimeout) or has
// no sshd entries; anyone can write an sshd line to them with logger(1),
// so verified is false. source names what was read, and why.
func (LinuxCollector) ScanAuthLogs(ctx context.Context, src Source, logPaths []string, since time.Time, sink func() func(line string)) (source string, verified bool, err error) {
	n, jerr := scanJournal(ctx, src, since, sink)
	var why string
	timedOut := errors.Is(jerr, ErrTimeout) || errors.Is(jerr, context.DeadlineExceeded) || errors.Is(jerr, ErrTruncated)
	switch {
	case jerr == nil && n > 0:
		return "journald", true, nil
	case jerr == nil:
		why = "journald has no sshd entries"
	case errors.Is(jerr, ErrTruncated):
		why = "journald was cut short (" + jerr.Error() + "), fell back"
	case timedOut:
		why = "journald timed out after " + JournalTimeout.String() + ", fell back"
	default:
		why = "journald unavailable (" + jerr.Error() + ")"
	}
	files := authLogFiles(src, logPaths, since)
	if len(files) == 0 {
		switch {
		case jerr == nil: // nothing else to read: journald's answer stands
			return "journald", true, nil
		case timedOut: // keep what journald gave
			return "journald (" + why + " to nothing: no text auth log)", true, jerr
		}
		return "none (no auth log readable and " + why + ")", false, jerr
	}
	fn := sink()
	var used, unread []string
	var cut, uerr error
	sshd := 0
	for _, f := range files {
		// A file that fails half way (a line over MaxLineBytes) gave its
		// earlier lines: it counts as read, cut short.
		lines := 0
		err := ScanLinesUnmasked(src, f, func(l string) {
			lines++
			if reSSHDLine.MatchString(l) {
				sshd++
			}
			fn(l)
		})
		switch {
		case err == nil:
			used = append(used, f)
		case lines > 0:
			used = append(used, f+" (cut short)")
			if cut == nil {
				cut = fmt.Errorf("%w: %s: %v", ErrTruncated, f, err)
			}
		default:
			unread = append(unread, f+" ("+string(Classify(err))+")")
			if uerr == nil {
				uerr = err
			}
		}
	}
	switch {
	case sshd > 0 || (jerr != nil && len(used) > 0):
		return strings.Join(used, ",") + " (unverified: " + why + "; " + unverifiedText + ")", false, cut
	case len(used) > 0: // journald and the text logs agree: no sshd entries
		return "journald", true, nil
	}
	// The text logs could not be read: an empty journal is not "no failed logins".
	return "none (" + why + "; " + strings.Join(unread, ",") + " unreadable)", false, uerr
}

// scanJournal reads the ssh and sshd units since since, at most
// JournalTimeout, and counts the sshd lines. A journal that hides the
// system's entries from this user is a permission error, not an empty one.
func scanJournal(ctx context.Context, src Source, since time.Time, sink func() func(line string)) (n int, err error) {
	ctx, cancel := context.WithTimeout(ctx, JournalTimeout)
	defer cancel()
	fn := sink()
	var res CmdResult
	for _, base := range [][]string{journalArgv, journalBinArgv} {
		argv := append([]string(nil), base...)
		argv[6] = since.UTC().Format("2006-01-02 15:04:05") + " UTC" // journalctl reads a bare time as local
		res, err = RunLinesUnmasked(ctx, src, argv, func(l string) {
			if reSSHDLine.MatchString(l) {
				n++
			}
			fn(l)
		})
		if !errors.Is(err, fs.ErrNotExist) {
			break // found (a missing binary is the only reason to try the other path)
		}
	}
	if err == nil && res.ExitCode != 0 {
		err = &exitError{res.ExitCode}
	}
	if err == nil && n == 0 && strings.Contains(res.Stderr, "not seeing messages from other users and the system") {
		err = fmt.Errorf("%w: journald hides the system's entries from this user", fs.ErrPermission)
	}
	return n, err
}

// authLogFiles are the text auth logs among logPaths changed since since.
func authLogFiles(src Source, logPaths []string, since time.Time) []string {
	var out []string
	for _, pattern := range logPaths {
		if !strings.Contains(pattern, "auth") && !strings.Contains(pattern, "secure") {
			continue
		}
		for _, f := range append(Glob(src, pattern+".1"), Glob(src, pattern)...) {
			if st, err := Stat(src, f); err == nil && !st.ModTime.Before(since) {
				out = append(out, f)
			}
		}
	}
	return out
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

// total is the space-saving counter: what was seen, plus what the source
// it replaced had (inherited, as Uncertainty), so a newcomer is not
// always the next to go and a slow source among a flood keeps its rank.
func (a *sshAgg) total() int { return a.Failed + a.InvalidUser + a.Accepted + a.Uncertainty }

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
	user = MaskSecrets(user) // masked whole, then cut: a cut secret would no longer match its rule
	if len(user) > 64 {
		user = CutString(user, 64)
	}
	if c.onlyIP != "" && ip != c.onlyIP {
		return
	}
	s := c.by[ip]
	if s == nil {
		inherited := 0
		if len(c.by) >= MaxTrackedSources {
			inherited = c.evict()
		}
		s = &sshAgg{SSHSource: SSHSource{IP: ip, First: ts, Uncertainty: inherited}, users: map[string]map[string]bool{"failed": {}, "invalid": {}, "accepted": {}}}
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
// It returns the victim's counter, which the newcomer inherits.
func (c *SSHLogins) evict() int {
	if c.low.Len() == 0 {
		return 0
	}
	victim := heap.Pop(&c.low).(*sshAgg)
	delete(c.by, victim.IP)
	c.evicted++
	return victim.total()
}

// Evicted is how many sources were dropped to stay within the bound.
func (c *SSHLogins) Evicted() int { return c.evicted }

// Result is the 50 busiest sources (failed + invalid, plus Uncertainty when
// sources were evicted), ties by IP.
func (c *SSHLogins) Result() []SSHSource {
	list := make([]SSHSource, 0, len(c.by))
	for _, s := range c.by {
		names := func(kind string) []string {
			var l []string
			for u := range s.users[kind] {
				l = append(l, u) // masked in Add
			}
			sort.Strings(l)
			return l
		}
		out := s.SSHSource
		out.FailedUsers, out.InvalidUsers, out.AcceptedUsers = names("failed"), names("invalid"), names("accepted")
		list = append(list, out)
	}
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i].Failed+list[i].InvalidUser+list[i].Uncertainty, list[j].Failed+list[j].InvalidUser+list[j].Uncertainty
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
	var agg *SSHLogins
	source, verified, err := c.ScanAuthLogs(ctx, src, logPaths, since, func() func(string) {
		agg = NewSSHLogins(since, at, "")
		return agg.Add
	})
	ev := AuthEvents{WindowHours: 24, FailedBySrc: map[string]int{}}
	for _, s := range agg.Result() {
		if n := s.Failed + s.InvalidUser; n > 0 {
			ev.FailedBySrc[s.IP] = n
		}
	}
	if source != "" && !strings.HasPrefix(source, "none") {
		switch {
		case errors.Is(err, ErrTruncated):
			return Partial(ev, ReasonTruncated, "from "+source+": "+err.Error())
		case errors.Is(err, ErrTimeout), errors.Is(err, context.DeadlineExceeded):
			return Partial(ev, ReasonTimeout, "from "+source)
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
	if !verified {
		return Partial(ev, ReasonUnverified, detail)
	}
	return Obs[AuthEvents]{Status: StatusOK, Detail: detail, Value: ev}
}
