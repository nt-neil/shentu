package hostenv

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"
)

const (
	cur1 = "s=0123456789abcdef0123456789abcdef;i=1;b=0123456789abcdef0123456789abcdef;m=1;t=1;x=1"
	cur2 = "s=0123456789abcdef0123456789abcdef;i=2;b=0123456789abcdef0123456789abcdef;m=2;t=2;x=2"
)

func journalLine(cursor, unit, uid, msg string) string {
	return `{"__CURSOR":"` + cursor + `","__REALTIME_TIMESTAMP":"1794700000000000","_SYSTEMD_UNIT":"` + unit + `","_UID":"` + uid + `","_PID":"812","_COMM":"php-fpm8.2","_TRANSPORT":"stderr","MESSAGE":"` + msg + `"}`
}

func journalArgvFor(after string, fields bool) []string {
	a := journalUnitArgv("/usr/bin/journalctl", after != "", fields)
	a[2] = "php8.2-fpm.service"
	if after != "" {
		a[4] = after
	} else {
		a[4] = "2026-11-15 00:00:00 UTC"
	}
	return a
}

// Every read shape is on the allowlist, with a unit and a cursor in their
// slots; an option where the unit goes, or a made-up cursor, is not.
func TestJournalUnitAllowlist(t *testing.T) {
	r, err := NewRunner(LinuxCollector{}.Allowlist())
	if err != nil {
		t.Fatal(err)
	}
	for _, after := range []string{"", cur1} {
		for _, fields := range []bool{true, false} {
			if a := journalArgvFor(after, fields); !r.Allowed(a) {
				t.Errorf("not allowlisted: %q", a)
			}
		}
	}
	bad := journalArgvFor(cur1, true)
	bad[2] = "--file=/etc/shadow.service"
	if r.Allowed(bad) {
		t.Errorf("an option in the unit's slot was allowed: %q", bad)
	}
	bad = journalArgvFor("s=x;--root=/", true)
	if r.Allowed(bad) {
		t.Errorf("a made-up cursor was allowed: %q", bad)
	}
}

func TestReadJournal(t *testing.T) {
	h := newFake(true)
	out := journalLine(cur1, "php8.2-fpm.service", "33", `PHP Warning:  include(): Failed opening '/etc/passwd' in /var/www/a.php on line 4`) + "\n" +
		`{"__CURSOR":"` + cur2 + `","MESSAGE":[104,105],"_UID":"0","_SYSTEMD_UNIT":"php8.2-fpm.service"}` + "\n"
	h.cmds[argvKey(journalArgvFor("", true))] = CmdResult{Stdout: []byte(out)}
	var got []JournalEntry
	since := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	last, err := ReadJournal(context.Background(), h, "php8.2-fpm.service", "", since, func(e JournalEntry) error {
		got = append(got, e)
		return nil
	})
	if err != nil || last != cur2 || len(got) != 2 {
		t.Fatalf("last %q, err %v, %d entries", last, err, len(got))
	}
	if e := got[0]; e.UID != 33 || e.PID != 812 || e.Unit != "php8.2-fpm.service" || e.Transport != "stderr" || !strings.Contains(e.Message, "a.php on line 4") || e.Time.IsZero() {
		t.Errorf("first entry %+v", e)
	}
	if got[1].Message != "hi" || got[1].UID != 0 {
		t.Errorf("binary MESSAGE %+v", got[1])
	}
	// Stopped by the consumer: the cursor of the last entry it took.
	last, err = ReadJournal(context.Background(), h, "php8.2-fpm.service", "", since, func(e JournalEntry) error {
		if e.Cursor == cur2 {
			return ErrStopJournal
		}
		return nil
	})
	if err != nil || last != cur1 {
		t.Errorf("stopped: last %q, err %v; want the first cursor", last, err)
	}
}

// systemd older than 236 has no --output-fields: read again without it.
func TestReadJournalOldSystemd(t *testing.T) {
	h := newFake(true)
	h.cmds[argvKey(journalArgvFor(cur1, true))] = CmdResult{ExitCode: 1, Stderr: "journalctl: unrecognized option '--output-fields=MESSAGE'"}
	h.cmds[argvKey(journalArgvFor(cur1, false))] = CmdResult{Stdout: []byte(journalLine(cur2, "php8.2-fpm.service", "0", "x") + "\n")}
	last, err := ReadJournal(context.Background(), h, "php8.2-fpm.service", cur1, time.Time{}, func(JournalEntry) error { return nil })
	if err != nil || last != cur2 {
		t.Errorf("last %q, err %v", last, err)
	}
}

func TestReadJournalHidden(t *testing.T) {
	h := newFake(false)
	h.cmds[argvKey(journalArgvFor(cur1, true))] = CmdResult{Stderr: "Hint: You are currently not seeing messages from other users and the system."}
	_, err := ReadJournal(context.Background(), h, "php8.2-fpm.service", cur1, time.Time{}, func(JournalEntry) error { return nil })
	if err == nil || !errors.Is(err, fs.ErrPermission) {
		t.Errorf("err %v, want a permission error", err)
	}
}

func TestAppUnits(t *testing.T) {
	h := newFake(true)
	h.links["/etc/systemd/system/multi-user.target.wants/php8.2-fpm.service"] = "/lib/systemd/system/php8.2-fpm.service"
	h.files["/lib/systemd/system/php8.2-fpm.service"] = "[Service]\nExecStart=/usr/sbin/php-fpm8.2 --nodaemonize --fpm-config /etc/php/8.2/fpm/php-fpm.conf\n"
	h.files["/etc/systemd/system/multi-user.target.wants/shop.service"] = "[Service]\nUser=www-data\nExecStart=/srv/shop/venv/bin/python -m gunicorn shop.wsgi\n"
	h.files["/etc/systemd/system/multi-user.target.wants/api.service"] = "[Service]\nExecStart=-/usr/bin/node /srv/api/index.js\n"
	h.files["/etc/systemd/system/multi-user.target.wants/cron.service"] = "[Service]\nExecStart=/usr/sbin/cron -f\n"
	sh := statHost{fakeHost: h, st: map[string]FileStat{"/etc/systemd/system/multi-user.target.wants": {Mode: fs.ModeDir | 0o755}}}
	o := LinuxCollector{}.AppUnits(sh)
	want := []AppUnit{{Name: "api.service"}, {Name: "php8.2-fpm.service", FPM: true}, {Name: "shop.service", User: "www-data"}}
	if o.Status != StatusOK || len(o.Value) != 3 || o.Value[0] != want[0] || o.Value[1] != want[1] || o.Value[2] != want[2] {
		t.Errorf("%s %s: %+v", o.Status, o.Detail, o.Value)
	}
	if !o.Value[0].RunsAppAsRoot() || o.Value[1].RunsAppAsRoot() || o.Value[2].RunsAppAsRoot() {
		t.Error("RunsAppAsRoot: want only node without User=")
	}
}

// What may run the application as root, whatever User= says, fails closed.
func TestAppUnitsElevated(t *testing.T) {
	h := newFake(true)
	wants := "/etc/systemd/system/multi-user.target.wants/"
	h.files[wants+"plus.service"] = "[Service]\nUser=www-data\nExecStart=+/usr/bin/node /srv/a.js\n"
	h.files[wants+"fpmr.service"] = "[Service]\nExecStart=/usr/sbin/php-fpm8.2 -R --nodaemonize\n"
	h.files[wants+"drop.service"] = "[Service]\nUser=www-data\nExecStart=/usr/bin/gunicorn app\n"
	h.files["/etc/systemd/system/drop.service.d/override.conf"] = "[Service]\nUser=root\n"
	h.files[wants+"hidden.service"] = "[Service]\nUser=www-data\nExecStart=/usr/bin/uwsgi app.ini\n"
	h.files["/etc/systemd/system/hidden.service.d/x.conf"] = "[Service]\nUser=root\n"
	h.denied["/etc/systemd/system/hidden.service.d/x.conf"] = true
	h.files[wants+"ok.service"] = "[Service]\nUser=www-data\nExecStart=/usr/bin/gunicorn app\n"
	sh := statHost{fakeHost: h, st: map[string]FileStat{
		"/etc/systemd/system/multi-user.target.wants": {Mode: fs.ModeDir | 0o755},
		"/etc/systemd/system/drop.service.d":          {Mode: fs.ModeDir | 0o755},
		"/etc/systemd/system/hidden.service.d":        {Mode: fs.ModeDir | 0o755},
	}}
	got := map[string]AppUnit{}
	for _, u := range (LinuxCollector{}).AppUnits(sh).Value {
		got[u.Name] = u
	}
	for name, root := range map[string]bool{"plus.service": true, "fpmr.service": true, "drop.service": true, "hidden.service": true, "ok.service": false} {
		if u, ok := got[name]; !ok || u.RunsAppAsRoot() != root {
			t.Errorf("%s: %+v (listed %v), RunsAppAsRoot want %v", name, u, ok, root)
		}
	}
	if got["drop.service"].User != "root" {
		t.Errorf("drop-in User= not applied: %+v", got["drop.service"])
	}
}

// A PHP-FPM pool running as root makes the master's messages no proof.
func TestAppUnitsFPMPoolRoot(t *testing.T) {
	h := newFake(true)
	h.files["/etc/systemd/system/multi-user.target.wants/php8.2-fpm.service"] = "[Service]\nExecStart=/usr/sbin/php-fpm8.2 --nodaemonize\n"
	h.files["/etc/php/8.2/fpm/php-fpm.conf"] = "[global]\ninclude=/etc/php/8.2/fpm/pool.d/*.conf\n"
	h.files["/etc/php/8.2/fpm/pool.d/www.conf"] = "[www]\nuser = root\n"
	sh := statHost{fakeHost: h, st: map[string]FileStat{"/etc/systemd/system/multi-user.target.wants": {Mode: fs.ModeDir | 0o755}}}
	us := LinuxCollector{}.AppUnits(sh).Value
	if len(us) != 1 || !us[0].FPM || !us[0].RunsAppAsRoot() {
		t.Errorf("%+v: want FPM, running as root", us)
	}
}
