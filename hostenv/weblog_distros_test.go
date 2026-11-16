package hostenv

import (
	"fmt"
	"io/fs"
	"strings"
	"testing"
)

// The default installs probed on GitHub runners (plan 0743f0 notes n10 and
// n11): owners, groups and modes of the log directories and files as apt or
// dnf and logrotate leave them. ptrace_scope was not probed: both values.
// Debian 12's Apache and its /var/log were not probed either: they are
// Ubuntu 24.04's here, to be measured in P6.
func distroHost(distro string, ptrace int, rotated bool) statHost {
	h := statHost{fakeHost: newFake(true), st: map[string]FileStat{}, acl: map[string]bool{}}
	g := func(n int) *int { return &n }
	dir := func(p string, mode fs.FileMode, uid, gid int) {
		h.st[p] = FileStat{Mode: fs.ModeDir | mode, UID: uid, GID: g(gid)}
	}
	file := func(p string, mode fs.FileMode, uid, gid int) {
		h.files[p] = ""
		h.st[p] = FileStat{Mode: mode, UID: uid, GID: g(gid)}
	}
	h.files["/proc/sys/kernel/yama/ptrace_scope"] = fmt.Sprintf("%d\n", ptrace)
	dir("/", 0o755, 0, 0)
	dir("/var", 0o755, 0, 0)
	dir("/etc", 0o755, 0, 0)
	switch distro {
	case "debian12", "ubuntu2404": // Debian 12: Apache and /var/log as Ubuntu's, until P6 measures them
		h.files["/etc/passwd"] = "root:x:0:0::/root:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\nsyslog:x:102:102::/:/usr/sbin/nologin\n"
		h.files["/etc/group"] = "root:x:0:\nadm:x:4:syslog\nwww-data:x:33:\nsyslog:x:102:\n"
		h.files["/etc/nsswitch.conf"] = "passwd: files systemd\ngroup: files systemd\nshadow: files\n"
		if distro == "ubuntu2404" {
			dir("/var/log", 0o775, 0, 102) // root:syslog
		} else {
			dir("/var/log", 0o755, 0, 0)
		}
		h.files["/etc/nginx/nginx.conf"] = "user www-data;\nhttp {\n\taccess_log /var/log/nginx/access.log;\n\terror_log /var/log/nginx/error.log;\n}\n"
		dir("/var/log/nginx", 0o755, 0, 4)
		file("/var/log/nginx/access.log", 0o640, 33, 4) // create 0640 www-data adm
		file("/var/log/nginx/error.log", 0o640, 33, 4)
		h.files["/etc/apache2/apache2.conf"] = "ErrorLog ${APACHE_LOG_DIR}/error.log\nCustomLog ${APACHE_LOG_DIR}/access.log combined\nLogFormat \"%h %l %u %t \\\"%r\\\" %>s %O\" combined\n"
		h.files["/etc/apache2/envvars"] = "export APACHE_RUN_USER=www-data\nexport APACHE_LOG_DIR=/var/log/apache2$SUFFIX\n"
		dir("/var/log/apache2", 0o750, 0, 4)
		file("/var/log/apache2/access.log", 0o640, 0, 4) // create 640 root adm
		file("/var/log/apache2/error.log", 0o640, 0, 4)
	case "rocky9":
		h.files["/etc/passwd"] = "root:x:0:0::/root:/bin/bash\nnginx:x:999:996::/var/lib/nginx:/sbin/nologin\napache:x:48:48::/usr/share/httpd:/sbin/nologin\n"
		h.files["/etc/group"] = "root:x:0:\nnginx:x:996:\napache:x:48:\n"
		h.files["/etc/nsswitch.conf"] = "passwd: files sss systemd\ngroup: files sss systemd\n"
		dir("/var/log", 0o755, 0, 0)
		h.files["/etc/nginx/nginx.conf"] = "user nginx;\nerror_log /var/log/nginx/error.log;\nhttp {\n\taccess_log /var/log/nginx/access.log;\n}\n"
		dir("/var/log/nginx", 0o711, 0, 0)
		if rotated { // after logrotate -f (n11)
			file("/var/log/nginx/access.log", 0o640, 999, 0) // create 0640 nginx root
			file("/var/log/nginx/error.log", 0o644, 999, 0)
			file("/var/log/nginx/access.log.1", 0o644, 0, 0) // the file the root master wrote, renamed
		} else {
			file("/var/log/nginx/access.log", 0o644, 0, 0) // written first by the root master
			file("/var/log/nginx/error.log", 0o644, 0, 0)
		}
		h.files["/etc/httpd/conf/httpd.conf"] = "User apache\nGroup apache\nErrorLog \"logs/error_log\"\nLogFormat \"%h %l %u %t \\\"%r\\\" %>s %b\" common\nCustomLog \"logs/access_log\" common\n"
		dir("/etc/httpd", 0o755, 0, 0)
		h.links["/etc/httpd/logs"] = "../../var/log/httpd"
		dir("/var/log/httpd", 0o700, 0, 0)
		file("/var/log/httpd/access_log", 0o644, 0, 0)
		file("/var/log/httpd/error_log", 0o644, 0, 0)
	}
	return h
}

func TestWebLogsDistroDefaults(t *testing.T) {
	type row struct {
		distro, log string
		rotated     bool
		ptrace      int
		want        Reason // "" verified
	}
	var rows []row
	for _, p := range []int{1, 0} {
		wuw := Reason("")
		if p == 0 {
			wuw = ReasonWebUserWritable // root's file, held open by workers the web user can ptrace
		}
		rows = append(rows,
			row{"debian12", "nginx access /var/log/nginx/access.log", false, p, ReasonWebUserWritable},
			row{"debian12", "apache access /var/log/apache2/access.log", false, p, wuw},
			row{"ubuntu2404", "nginx access /var/log/nginx/access.log", false, p, ReasonWebUserWritable},
			row{"ubuntu2404", "apache access /var/log/apache2/access.log", false, p, wuw},
			row{"rocky9", "nginx access /var/log/nginx/access.log", false, p, wuw},
			row{"rocky9", "nginx access /var/log/nginx/access.log", true, p, ReasonWebUserWritable},
			row{"rocky9", "apache access /etc/httpd/logs/access_log", false, p, wuw},
		)
	}
	var table []string
	for _, r := range rows {
		m := webLogsByKey(t, LinuxCollector{}.WebLogs(distroHost(r.distro, r.ptrace, r.rotated)))
		s, ok := m[r.log]
		if !ok {
			t.Errorf("%s: %s not found among %v", r.distro, r.log, m)
			continue
		}
		table = append(table, fmt.Sprintf("%s rotated=%v ptrace_scope=%d %s: verified=%v reason=%q", r.distro, r.rotated, r.ptrace, r.log, s.Verified, s.Reason))
		if s.Reason != r.want || s.Verified != (r.want == "") {
			t.Errorf("%s rotated=%v ptrace=%d %s: verified %v %q (%s); want %q", r.distro, r.rotated, r.ptrace, r.log, s.Verified, s.Reason, s.Detail, r.want)
		}
		if !s.Verified && ReasonMeaningZh[s.Reason] == "" {
			t.Errorf("%s: reason %q has no explanation for the alert", r.log, s.Reason)
		}
	}
	t.Log("\n" + strings.Join(table, "\n"))

	// Rocky after rotation: the error log is nginx's (999:0 644), and so not
	// verified on two counts; the renamed access.log.1 is root's (0:0 644)
	// and passes as a file, but the reader never trusts a rotated file more
	// than its log (detect: TestReadLogRotatedCeiling), here web_user_writable.
	h := distroHost("rocky9", 1, true)
	m := webLogsByKey(t, LinuxCollector{}.WebLogs(h))
	if e := m["nginx error /var/log/nginx/error.log"]; e.Verified || e.Reason != ReasonWebUserWritable {
		t.Errorf("rocky9 rotated error.log: %+v", e)
	}
	if r := JudgeLog(h, "/var/log/nginx/access.log.1", LinuxCollector{}.WebAccounts(h)); !r.Verified {
		t.Errorf("rocky9 access.log.1 as a file: %+v", r)
	}
}
