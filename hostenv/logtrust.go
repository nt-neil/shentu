package hostenv

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// LogTrustSuggestion is one change an operator may make so that more of
// the web logs can be verified, and so back a block. shentu prints it
// (shentu log-trust suggest) and never applies it: changing the web
// server, journald or the kernel is the operator's to do and to undo.
type LogTrustSuggestion struct {
	ID      string `json:"id"`
	Applies string `json:"applies"` // why it applies to this host
	File    string `json:"file"`    // where the snippet goes
	Snippet string `json:"snippet"`
	Then    string `json:"then,omitempty"` // the command that makes it take effect
	Stops   string `json:"stops"`          // the forging it stops
	Costs   string `json:"costs"`          // what it changes beside
}

// LogTrustSuggestions are the suggestions that apply to src, in the order
// they are best applied: nginx's log through journald (and journald not
// dropping it), ptrace_scope 1, and PHP-FPM pools of their own accounts.
func (c LinuxCollector) LogTrustSuggestions(src Source) []LogTrustSuggestion {
	logs := c.WebLogs(src).Value
	l := &logLoader{src: src, conf: logConf, out: map[string]*LogSource{}}
	l.nginx()
	l.apache()
	l.phpFPM()
	l.lighttpd()
	l.unitUsers(c, src)
	l.runAsAccounts()
	l.webAccounts()
	var out []LogTrustSuggestion

	ngxFile, ngxJournal := false, false // an nginx access log in a file, and one verified through journald
	var why []string
	for _, s := range logs {
		if s.Server != "apache" || s.Kind != "access" || s.Verified {
			continue
		}
		why = append(why, s.Path+": "+string(s.Reason))
	}
	for _, s := range logs {
		if s.Server != "nginx" || s.Kind != "access" {
			continue
		}
		switch {
		case s.Journal != "" && s.Verified:
			ngxJournal = true
		case s.Journal == "" && !s.Verified:
			ngxFile = true
			why = append(why, s.Path+": "+string(s.Reason))
		}
	}
	if ngxFile && !ngxJournal && exists(src, "/etc/nginx/nginx.conf") {
		tag := "nginx"
		if len(l.ngxSyslog[tag]) > 0 { // the tag is taken: the line is to be its tag's only log
			tag = "shentu_access"
		}
		dest := "syslog:server=unix:/dev/log,nohostname"
		if tag != "nginx" {
			dest += ",tag=" + tag
		}
		out = append(out, LogTrustSuggestion{
			ID:      "nginx-journald",
			Applies: "nginx's access log is not verified (" + strings.Join(why, "; ") + ")",
			File:    "/etc/nginx/nginx.conf, in the http block, beside the access_log there",
			Snippet: "access_log " + dest + " combined;",
			Then:    "nginx -t && systemctl reload nginx",
			Stops: "a web account writing lines into the log file: journald records each line with the sender's unit, account and program, " +
				"which no process can set, and shentu takes a line as nginx's only when all three are its workers'. The file stays as it is, still unverified.",
			Costs: "every request is written twice (file and journal); nginx cuts a syslog line past its length limit, and a cut line is judged undetermined.",
		})
		out = append(out, LogTrustSuggestion{
			ID:      "journald-rate-limit",
			Applies: "with nginx-journald: journald keeps at most 10000 entries per 30 s from a unit by default, and drops the rest",
			File:    "/etc/systemd/system/nginx.service.d/shentu-log-rate.conf",
			Snippet: "[Service]\nLogRateLimitIntervalSec=0",
			Then:    "systemctl daemon-reload && systemctl restart nginx",
			Stops:   "losing the lines of a busy moment, attacks among them: a dropped line is never judged (it cannot block the wrong address, but the attack goes unseen).",
			Costs:   "the journal grows with the traffic: set SystemMaxUse= in journald.conf to keep it bounded.",
		})
	}

	b, err := src.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	scope := strings.TrimSpace(string(b))
	if n, e := strconv.Atoi(scope); err == nil && e == nil && n < 1 {
		var held []string
		for _, s := range logs {
			if s.Kind == "access" && !s.Verified && strings.Contains(s.Detail, "ptrace_scope") {
				held = append(held, s.Path)
			}
		}
		applies := "kernel.yama.ptrace_scope is " + scope + ": a process may trace any other of its own account"
		if len(held) > 0 {
			applies += "; it alone keeps " + strings.Join(held, ", ") + " unverified"
		}
		out = append(out, LogTrustSuggestion{
			ID:      "ptrace-scope",
			Applies: applies,
			File:    "/etc/sysctl.d/60-shentu-ptrace.conf",
			Snippet: "kernel.yama.ptrace_scope = 1",
			Then:    "sysctl --system",
			Stops:   "application code (PHP running as the web account) tracing the web server's workers, which hold the logs open, and writing lines through them.",
			Costs:   "an account can no longer attach a debugger to its own running processes (gdb -p, strace -p) unless it is their parent, or root.",
		})
	}

	servers := map[string]bool{}
	for _, us := range l.serverUsers {
		for _, u := range us {
			servers[u] = true
		}
	}
	var shared []string
	for _, u := range l.fpmUsers {
		if (servers[u] || sharedWebUsers[u]) && !contains(shared, u) {
			shared = append(shared, u)
		}
	}
	if len(shared) > 0 {
		server := "the web server's account"
		if us := l.serverUsers["nginx"]; len(us) == 1 {
			server = us[0]
		}
		out = append(out, LogTrustSuggestion{
			ID:      "fpm-pool-account",
			Applies: "PHP-FPM runs pools as " + strings.Join(shared, ", ") + ", the web server's or a shared web account",
			File:    "the pool's file (/etc/php/*/fpm/pool.d/*.conf, /etc/php-fpm.d/*.conf), after: useradd --system --no-create-home --shell /usr/sbin/nologin php-app",
			Snippet: "user = php-app\ngroup = php-app\nlisten.owner = " + server + "\nlisten.group = " + server + "\nlisten.mode = 0660",
			Then:    "systemctl restart the PHP-FPM unit",
			Stops:   "PHP, if broken into, writing or tracing what the web server's workers hold: they then run as another account.",
			Costs:   "the application's files must be readable by php-app, and what it writes (uploads, cache) owned by it.",
		})
	}
	return out
}

var suppressed = regexp.MustCompile(`^Suppressed (\d+) messages from (\S+)$`)

// JournalSuppressed is how many messages journald dropped from unit since
// then by its rate limit, as systemd-journald's own entries say.
func JournalSuppressed(ctx context.Context, src Source, unit string, since time.Time) (int, error) {
	n := 0
	_, err := ReadJournal(ctx, src, "systemd-journald.service", "", since, func(e JournalEntry) error {
		if m := suppressed.FindStringSubmatch(e.Message); m != nil && m[2] == unit {
			k, _ := strconv.Atoi(m[1])
			n += k
		}
		return nil
	})
	return n, err
}
