package hostenv

import (
	"context"
	"strings"
	"testing"
	"time"
)

func suggestionIDs(ss []LogTrustSuggestion) []string {
	var ids []string
	for _, s := range ss {
		ids = append(ids, s.ID)
	}
	return ids
}

func TestLogTrustSuggestions(t *testing.T) {
	debianFPM := func(h statHost) {
		h.files["/etc/php/8.2/fpm/php-fpm.conf"] = "include=/etc/php/8.2/fpm/pool.d/*.conf\n"
		h.files["/etc/php/8.2/fpm/pool.d/www.conf"] = "[www]\nuser = www-data\ngroup = www-data\n"
	}
	rows := []struct {
		name string
		host func() statHost
		want string
	}{
		{"Debian 12, PHP-FPM as www-data", func() statHost { h := distroHost("debian12", 1, false); debianFPM(h); return h },
			"nginx-journald journald-rate-limit fpm-pool-account"},
		{"Rocky 9, ptrace_scope 0", func() statHost { return distroHost("rocky9", 0, false) },
			"nginx-journald journald-rate-limit ptrace-scope"},
		{"nginx already through journald", func() statHost { return journalHost(1) }, ""},
		{"Rocky 9, nginx apart, pool as Apache's apache", func() statHost { return serverHost(1, true) }, "fpm-pool-account"},
	}
	for _, r := range rows {
		got := strings.Join(suggestionIDs(LinuxCollector{}.LogTrustSuggestions(r.host())), " ")
		if got != r.want {
			t.Errorf("%s: %q, want %q", r.name, got, r.want)
		}
	}

	// The suggested line is what the journal channel then verifies.
	h := distroHost("ubuntu2404", 1, false)
	var line string
	for _, s := range (LinuxCollector{}).LogTrustSuggestions(h) {
		if s.ID == "nginx-journald" {
			line = s.Snippet
		}
	}
	if line != "access_log syslog:server=unix:/dev/log,nohostname combined;" {
		t.Fatalf("snippet %q", line)
	}
	j := journalHost(1)
	j.files["/etc/nginx/nginx.conf"] = "user www-data;\nhttp {\n\t" + line + "\n}\n"
	if s := webLogsByKey(t, LinuxCollector{}.WebLogs(j))["nginx access syslog:server=unix:/dev/log,nohostname"]; !s.Verified {
		t.Errorf("the suggested line, applied: %+v", s)
	}

	// The default tag taken by another log: the line gets its own.
	h = distroHost("debian12", 1, false)
	h.files["/etc/nginx/nginx.conf"] = "user www-data;\nerror_log syslog:server=unix:/dev/log,nohostname;\nhttp {\n\taccess_log /var/log/nginx/access.log;\n}\n"
	for _, s := range (LinuxCollector{}).LogTrustSuggestions(h) {
		if s.ID == "nginx-journald" && !strings.Contains(s.Snippet, "tag=shentu_access") {
			t.Errorf("tag taken: %q", s.Snippet)
		}
	}
}

// journaldHost answers every journalctl read with systemd-journald's own
// entries.
type journaldHost struct {
	*fakeHost
	out string
}

func (h journaldHost) Run(_ context.Context, argv []string) (CmdResult, error) {
	return CmdResult{Stdout: []byte(h.out)}, nil
}

func TestJournalSuppressed(t *testing.T) {
	e := func(c, msg string) string {
		return `{"__CURSOR":"` + c + `","_SYSTEMD_UNIT":"systemd-journald.service","_UID":"0","_TRANSPORT":"driver","MESSAGE":"` + msg + `"}`
	}
	h := journaldHost{fakeHost: newFake(true), out: strings.Join([]string{
		e("c1", "Suppressed 1200 messages from nginx.service"),
		e("c2", "Suppressed 7 messages from php8.2-fpm.service"),
		e("c3", "Suppressed 30 messages from nginx.service"),
		e("c4", "Journal started"),
	}, "\n") + "\n"}
	n, err := JournalSuppressed(context.Background(), h, "nginx.service", time.Now().Add(-time.Hour))
	if err != nil || n != 1230 {
		t.Errorf("suppressed %d, %v; want 1230", n, err)
	}
}
