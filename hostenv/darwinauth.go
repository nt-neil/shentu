package hostenv

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
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
// as "sshd-session", while /usr/libexec and /usr/sbin are SIP-protected.
// senderImagePath keeps the libraries' lines (pam, Open Directory) out.
const unifiedSSHPredicate = `(processImagePath == "/usr/libexec/sshd-session" AND senderImagePath == "/usr/libexec/sshd-session") OR ` +
	`(processImagePath == "/usr/sbin/sshd" AND senderImagePath == "/usr/sbin/sshd")`

// UnifiedSSHArgv reads those events since a local time ("--start" is
// read in the Mac's time zone). /usr/bin/log in full: in zsh, macOS's
// shell, "log" is a builtin.
var UnifiedSSHArgv = []string{"/usr/bin/log", "show", "--info", "--style", "syslog", "--predicate", unifiedSSHPredicate, "--start", SlotTime}

func init() { registerBig(UnifiedSSHArgv, 0, JournalTimeout) }

// UnifiedVerified is whether the unified log's sshd lines count as
// written by sshd. The predicate's image paths should make them so; it
// stays false until a VM confirms a copy at /tmp/sshd-session is not
// matched.
const UnifiedVerified = false

// unifiedExitDenied is log show's exit status for a user outside the
// admin group: "Could not open local log store: Operation not permitted".
const unifiedExitDenied = 77

// reUnifiedLine is a --style syslog line: "<date> <time+zone>  <host>
// <process>[<pid>]: <message>". The header and continuation lines (a tab
// first) do not match.
var reUnifiedLine = regexp.MustCompile(`^(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d(?:\.\d+)?[+-]\d{4}) +(\S+ \S+\[\d+\]: .*)$`)

// UnifiedToAuthLine rewrites a log show --style syslog line as an
// auth.log one, "<date>T<time+zone> <host> <process>[<pid>]: <message>",
// which sshdPrefix and ParseLogTime read; ok is false for any other line.
func UnifiedToAuthLine(l string) (string, bool) {
	m := reUnifiedLine.FindStringSubmatch(l)
	if m == nil {
		return "", false
	}
	return m[1] + "T" + m[2] + " " + m[3], true
}

// ScanAuthLogs streams sshd's login events since since from the unified
// log to a consumer from sink, as auth.log lines. A user outside the
// admin group is refused (fs.ErrPermission): root or an admin reads them.
func (DarwinCollector) ScanAuthLogs(ctx context.Context, src Source, since time.Time, sink func() func(line string)) (source string, verified bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, JournalTimeout)
	defer cancel()
	fn := sink()
	argv := append([]string(nil), UnifiedSSHArgv...)
	argv[len(argv)-1] = since.Local().Format("2006-01-02 15:04:05")
	res, err := RunLinesUnmasked(ctx, src, argv, func(l string) {
		if a, ok := UnifiedToAuthLine(l); ok {
			fn(a)
		}
	})
	source = "the unified log (sshd-session, sshd)"
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
