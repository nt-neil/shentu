package hostenv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"time"
)

// macOS keeps sshd's login events in its unified log, not in a text file
// (VM acceptance macos-m0-pr4, macOS 15.7.7, OpenSSH 9.9): the messages
// are sshd's own text, the same as in Linux's auth.log, written by
// /usr/libexec/sshd-session (older macOS: /usr/sbin/sshd) at the Info
// level, which log show leaves out without --info. The IPs are not
// redacted to <private>.
//
// The predicate names the program by its image path, not by process (its
// file name): any user can copy a program to /tmp/sshd-session and log
// as "sshd-session". That alone is not enough to trust the lines (N-186-1):
// any user can run the system's own /usr/sbin/sshd -D with a config and
// host key of their own on a high port, and its lines pass the predicate;
// userID 0 keeps those out (UnifiedVerified). senderImagePath keeps the
// libraries' lines (pam, Open Directory) out.
const unifiedSSHPredicate = `(processImagePath == "/usr/libexec/sshd-session" AND senderImagePath == "/usr/libexec/sshd-session") OR ` +
	`(processImagePath == "/usr/sbin/sshd" AND senderImagePath == "/usr/sbin/sshd")`

// UnifiedSSHArgv reads those events since a local time ("--start" is
// read in the Mac's time zone, VM macos-pr186 check 3; an hour early, for
// the hour a DST change repeats: the counts filter on since, S-186-2), one
// JSON object a line (ndjson: userID is in it, syslog style has none).
// /usr/bin/log in full: in zsh, macOS's shell, "log" is a builtin.
var UnifiedSSHArgv = []string{"/usr/bin/log", "show", "--info", "--style", "ndjson", "--predicate", unifiedSSHPredicate, "--start", SlotTime}

func init() { registerBig(UnifiedSSHArgv, 0, JournalTimeout) }

// UnifiedVerified: the lines kept are sshd's own, written by root. The
// image paths keep a copied program out (VM macos-pr186 check 2: a
// /tmp/sshd-session's lines carry /private/tmp/sshd-session); userID 0
// keeps a user's own /usr/sbin/sshd out (check 5: its login lines carry
// the user's uid, 501, the system sshd's carry 0). Only root can run an
// sshd whose lines carry 0, as on Linux (_UID=0).
const UnifiedVerified = true

// unifiedExitDenied is log show's exit status for a user outside the
// admin group: "Could not open local log store: Operation not permitted".
const unifiedExitDenied = 77

// Why an event was not counted: fixed words, said in the source.
const (
	UnifiedDropNotRoot  = "not_logged_by_root" // userID missing or not 0
	UnifiedDropNotSSHD  = "not_sshd_image"     // process and sender not one of the two sshd images
	UnifiedDropBadEvent = "unreadable_event"   // not a JSON event with a timestamp and a message
)

var unifiedImages = map[string]string{"/usr/libexec/sshd-session": "sshd-session", "/usr/sbin/sshd": "sshd"}

// reUnifiedTime is ndjson's timestamp: "2006-01-02 15:04:05.000000-0700".
var reUnifiedTime = regexp.MustCompile(`^(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d(?:\.\d+)?[+-]\d{4})$`)

// UnifiedToAuthLine rewrites one log show --style ndjson event as an
// auth.log line, "<date>T<time+zone> localhost <process>[<pid>]:
// <message>", which sshdPrefix and ParseLogTime read. drop is why it is
// not one (a Unified* word), "" for a line that is not an event at all.
func UnifiedToAuthLine(l string) (line, drop string) {
	l = strings.TrimSpace(l)
	if !strings.HasPrefix(l, "{") {
		return "", "" // not an event (log show prints none today)
	}
	var e struct {
		Timestamp        string `json:"timestamp"`
		ProcessImagePath string `json:"processImagePath"`
		SenderImagePath  string `json:"senderImagePath"`
		EventMessage     string `json:"eventMessage"`
		ProcessID        int64  `json:"processID"`
		UserID           *int64 `json:"userID"`
	}
	if json.Unmarshal([]byte(l), &e) != nil {
		return "", UnifiedDropBadEvent
	}
	name, ok := unifiedImages[e.ProcessImagePath]
	if !ok || e.SenderImagePath != e.ProcessImagePath {
		return "", UnifiedDropNotSSHD
	}
	if e.UserID == nil || *e.UserID != 0 {
		return "", UnifiedDropNotRoot
	}
	m := reUnifiedTime.FindStringSubmatch(e.Timestamp)
	msg, _, _ := strings.Cut(e.EventMessage, "\n")
	if m == nil || strings.TrimSpace(msg) == "" || e.ProcessID <= 0 {
		return "", UnifiedDropBadEvent
	}
	return fmt.Sprintf("%sT%s localhost %s[%d]: %s", m[1], m[2], name, e.ProcessID, msg), ""
}

// ScanAuthLogs streams sshd's login events since since from the unified
// log to a consumer from sink, as auth.log lines. A user outside the
// admin group is refused (fs.ErrPermission): root or an admin reads them.
// Events not counted are said in source, with their reasons.
func (DarwinCollector) ScanAuthLogs(ctx context.Context, src Source, since time.Time, sink func() func(line string)) (source string, verified bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, JournalTimeout)
	defer cancel()
	fn := sink()
	argv := append([]string(nil), UnifiedSSHArgv...)
	argv[len(argv)-1] = since.Add(-time.Hour).Local().Format("2006-01-02 15:04:05")
	drops := map[string]int{}
	res, err := RunLinesUnmasked(ctx, src, argv, func(l string) {
		a, drop := UnifiedToAuthLine(l)
		switch {
		case drop != "":
			drops[drop]++
		case a != "":
			fn(a)
		}
	})
	source = "the unified log (sshd-session, sshd; logged by root)"
	var said []string
	for _, w := range []string{UnifiedDropNotRoot, UnifiedDropNotSSHD, UnifiedDropBadEvent} {
		if n := drops[w]; n > 0 {
			said = append(said, fmt.Sprintf("%s %d", w, n))
		}
	}
	if len(said) > 0 {
		source += "; events not counted: " + strings.Join(said, ", ")
	}
	switch {
	case err == nil && res.ExitCode == unifiedExitDenied:
		err = fmt.Errorf("%w: log show: only root and members of the admin group can read the unified log", fs.ErrPermission)
	case err == nil && res.ExitCode != 0:
		err = &exitError{res.ExitCode}
	case errors.Is(err, context.DeadlineExceeded):
		err = fmt.Errorf("%w: log show took over %s", ErrTimeout, JournalTimeout)
	}
	return source, UnifiedVerified, err
}
