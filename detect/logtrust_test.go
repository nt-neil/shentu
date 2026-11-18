package detect

import (
	"context"
	"testing"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

// A log judged to be a server account's (hostenv.WebAccounts.ServerUIDs)
// stays verified while the file opened is still that account's; another
// owner, or a server account's file judged as root's, is not.
func TestOpenedServerOwner(t *testing.T) {
	const id = "1:2"
	rows := []struct {
		uid, judged int
		want        bool
	}{
		{999, 999, true},
		{rootUID, 999, true},
		{999, 0, false},
		{1000, 999, false},
	}
	for _, r := range rows {
		ok, _ := opened(hostenv.FileStat{Mode: 0o640, UID: r.uid, ID: id}, id, r.judged)
		if ok != r.want {
			t.Errorf("owner %d judged %d: %v, want %v", r.uid, r.judged, ok, r.want)
		}
	}
	if ok, _ := opened(hostenv.FileStat{Mode: 0o660, UID: 999, ID: id}, id, 999); ok {
		t.Errorf("group-writable file opened as verified")
	}
}

// syslogEntry is a journal entry as nginx's access_log to /dev/log gives it.
func syslogEntry(cursor, unit, uid, exe, ident, transport, msg string) string {
	return `{"__CURSOR":"` + cursor + `","__REALTIME_TIMESTAMP":"1794700000000000","_SYSTEMD_UNIT":"` + unit + `","_UID":"` + uid + `","_EXE":"` + exe + `","SYSLOG_IDENTIFIER":"` + ident + `","_TRANSPORT":"` + transport + `","MESSAGE":"` + msg + `"}`
}

// An entry of nginx's access log in journald is verified only when the
// source is and journald says nginx's workers sent it over syslog; the
// unit's other entries (another tag, systemd's own about it) are not its
// lines at all.
func TestScanJournalAccess(t *testing.T) {
	line := func(path string) string {
		return `192.0.2.10 - - [19/Nov/2026:02:00:00 +0000] \"GET ` + path + ` HTTP/1.1\" 200 5 \"-\" \"marker-agent\"`
	}
	const u, exe = "nginx.service", "/usr/sbin/nginx"
	src := &journalSrc{
		entries: []string{
			syslogEntry(jc1, u, "33", exe, "nginx", "syslog", line("/verified-marker")),
			syslogEntry(jc2, u, "33", "/usr/bin/logger", "nginx", "syslog", line("/logger-marker")),
			syslogEntry("c3", u, "0", exe, "nginx", "syslog", line("/root-marker")),
			syslogEntry("c4", u, "33", exe, "nginx", "journal", line("/journal-marker")),
			syslogEntry("c5", "php8.2-fpm.service", "33", exe, "nginx", "syslog", line("/fpm-marker")),
			syslogEntry("c6", u, "33", exe, "other-tag", "syslog", line("/other-tag-marker")),
			syslogEntry("c7", u, "1000", exe, "nginx", "syslog", line("/other-uid-marker")),
		},
		cursors: []string{jc1, jc2, "c3", "c4", "c5", "c6", "c7"},
	}
	ls := hostenv.LogSource{Path: "syslog:server=unix:/dev/log,nohostname", Server: "nginx", Kind: "access", Format: "combined",
		Spec: `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`,
		Verified: true, Journal: u, JournalTag: "nginx", JournalExe: exe, JournalUID: 33}
	got := map[string]bool{}
	scan := func(ls hostenv.LogSource) {
		got = map[string]bool{}
		_, _, sig, err := ScanJournalAccess(context.Background(), src, ls, nil, "", NewBudget(DefaultBudgetBytes, time.Minute), func(r AccessRecord, l Line) {
			got[r.Path] = l.Verified
		})
		if err != nil || sig.Unparsed.Count != 0 {
			t.Fatalf("scan: %v, %+v", err, sig)
		}
	}
	scan(ls)
	want := map[string]bool{"/verified-marker": true, "/logger-marker": false, "/root-marker": false, "/journal-marker": false, "/other-uid-marker": false}
	if len(got) != len(want) {
		t.Errorf("records %v, want %v", got, want)
	}
	for p, v := range want {
		if g, ok := got[p]; !ok || g != v {
			t.Errorf("%s: verified %v (seen %v), want %v", p, g, ok, v)
		}
	}
	ls.Verified = false // the source not verified: none of its entries is
	scan(ls)
	if got["/verified-marker"] {
		t.Errorf("an entry of an unverified source verified")
	}
}
