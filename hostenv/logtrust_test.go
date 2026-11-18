package hostenv

import (
	"io/fs"
	"strings"
	"testing"
)

// serverHost is Rocky 9's nginx (distroHost) with the account databases
// only in the files and a PHP-FPM pool of its own account: the server's
// account (nginx) is apart from the application's (apache) unless a row
// says otherwise.
func serverHost(ptrace int, rotated bool) statHost {
	h := distroHost("rocky9", ptrace, rotated)
	h.files["/etc/nsswitch.conf"] = "passwd: files systemd\ngroup: files systemd\n"
	h.files["/etc/php-fpm.conf"] = "include=/etc/php-fpm.d/*.conf\n"
	h.files["/etc/php-fpm.d/www.conf"] = "[www]\nuser = apache\ngroup = apache\nlisten.acl_users = apache,nginx\n"
	h.st["/etc/php-fpm.d"] = FileStat{Mode: fs.ModeDir | 0o755}
	return h
}

func TestServerAccountApart(t *testing.T) {
	const log = "nginx access /var/log/nginx/access.log"
	wants := "/etc/systemd/system/multi-user.target.wants"
	rows := []struct {
		name    string
		ptrace  int
		rotated bool
		edit    func(h statHost)
		want    Reason // "" verified
	}{
		// The server's own account, the pool another: nothing the
		// application runs as can write the file or ptrace the workers.
		{"rotated, nginx's file", 1, true, nil, ""},
		{"rotated, ptrace_scope 0", 0, true, nil, ""},
		{"root's file, ptrace_scope 0", 0, false, nil, ""},
		// Whatever makes the application's account the server's, or may.
		{"pool runs as nginx", 0, true, func(h statHost) {
			h.files["/etc/php-fpm.d/www.conf"] = "[www]\nuser = nginx\ngroup = apache\n"
		}, ReasonWebUserWritable},
		{"pool's group is nginx's", 0, true, func(h statHost) {
			h.files["/etc/php-fpm.d/www.conf"] = "[www]\nuser = apache\ngroup = nginx\n"
		}, ReasonWebUserWritable},
		{"pool's socket group is nginx's", 1, true, func(h statHost) {
			h.files["/etc/php-fpm.d/www.conf"] = "[www]\nuser = apache\nlisten.group = nginx\n"
		}, ReasonWebUserWritable},
		{"pool's account not in passwd", 1, true, func(h statHost) {
			h.files["/etc/php-fpm.d/www.conf"] = "[www]\nuser = appuser-marker\n"
		}, ReasonWebUserWritable},
		{"app unit runs as nginx", 1, true, func(h statHost) {
			h.st["/etc/systemd"] = FileStat{Mode: fs.ModeDir | 0o755}
			h.st["/etc/systemd/system"] = FileStat{Mode: fs.ModeDir | 0o755}
			h.st[wants] = FileStat{Mode: fs.ModeDir | 0o755}
			h.files[wants+"/marker.service"] = "[Service]\nUser=nginx\nExecStart=/usr/bin/gunicorn marker\n"
		}, ReasonWebUserWritable},
		{"any enabled unit runs as nginx", 1, true, func(h statHost) {
			systemdDirs(h)
			h.files[wants+"/marker.service"] = "[Service]\nUser=nginx\nExecStart=/usr/local/bin/marker-tool\n"
		}, ReasonWebUserWritable},
		{"a drop-in makes a unit run as nginx", 1, true, func(h statHost) {
			systemdDirs(h)
			h.files[wants+"/marker.service"] = "[Service]\nExecStart=/usr/local/bin/marker-tool\n"
			h.st["/etc/systemd/system/marker.service.d"] = FileStat{Mode: fs.ModeDir | 0o755}
			h.files["/etc/systemd/system/marker.service.d/user.conf"] = "[Service]\nUser=nginx\n"
		}, ReasonWebUserWritable},
		{"a timer's service runs as nginx", 1, true, func(h statHost) {
			systemdDirs(h)
			h.st["/etc/systemd/system/timers.target.wants"] = FileStat{Mode: fs.ModeDir | 0o755}
			h.links["/etc/systemd/system/timers.target.wants/marker.timer"] = "/usr/lib/systemd/system/marker.timer"
			h.files["/usr/lib/systemd/system/marker.timer"] = "[Timer]\nOnCalendar=daily\n"
			h.files["/usr/lib/systemd/system/marker.service"] = "[Service]\nUser=nginx\nExecStart=/usr/local/bin/marker-tool\n"
		}, ReasonWebUserWritable},
		{"a unit runs with nginx's group", 1, true, func(h statHost) {
			systemdDirs(h)
			h.files[wants+"/marker.service"] = "[Service]\nUser=root\nSupplementaryGroups=nginx\nExecStart=/usr/local/bin/marker-tool\n"
		}, ReasonWebUserWritable},
		{"a unit whose account its instance names", 1, true, func(h statHost) {
			systemdDirs(h)
			h.files[wants+"/marker@a.service"] = "[Service]\nUser=%i\nExecStart=/usr/local/bin/marker-tool\n"
		}, ReasonWebUserWritable},
		{"a unit not enabled runs as nginx", 1, true, func(h statHost) {
			systemdDirs(h)
			h.files["/usr/lib/systemd/system/marker.service"] = "[Service]\nUser=nginx\nExecStart=/usr/local/bin/marker-tool\n"
		}, ReasonWebUserWritable},
		{"a requires link to a unit as nginx", 1, true, func(h statHost) {
			systemdDirs(h)
			h.st["/etc/systemd/system/marker.target.requires"] = FileStat{Mode: fs.ModeDir | 0o755}
			h.files["/etc/systemd/system/marker.target.requires/marker.service"] = "[Service]\nUser=nginx\nExecStart=/usr/local/bin/marker-tool\n"
		}, ReasonWebUserWritable},
		{"a template's instance is nginx", 1, true, func(h statHost) {
			systemdDirs(h)
			h.files["/usr/lib/systemd/system/marker@.service"] = "[Service]\nUser=%i\nExecStart=/usr/local/bin/marker-tool\n"
			h.links[wants+"/marker@nginx.service"] = "/usr/lib/systemd/system/marker@.service"
		}, ReasonWebUserWritable},
		{"a template with no instance listed", 1, true, func(h statHost) {
			systemdDirs(h)
			h.files["/usr/lib/systemd/system/marker@.service"] = "[Service]\nUser=%I\nExecStart=/usr/local/bin/marker-tool\n"
		}, ReasonWebUserWritable},
		{"a user manager started for nginx's uid", 1, true, func(h statHost) {
			systemdDirs(h)
			h.files["/usr/lib/systemd/system/user@.service"] = "[Service]\nUser=%i\nExecStart=/usr/lib/systemd/systemd --user\n"
			h.links[wants+"/user@999.service"] = "/usr/lib/systemd/system/user@.service"
		}, ReasonWebUserWritable},
		{"systemd's user manager", 1, true, func(h statHost) {
			systemdDirs(h)
			h.files["/usr/lib/systemd/system/user@.service"] = "[Service]\nUser=%i\nExecStart=/usr/lib/systemd/systemd --user\n"
		}, ""},
		{"a unit's account by another specifier", 1, true, func(h statHost) {
			systemdDirs(h)
			h.files["/usr/lib/systemd/system/marker.service"] = "[Service]\nUser=%u\nExecStart=/usr/local/bin/marker-tool\n"
		}, ReasonWebUserWritable},
		{"unit directory not listed", 1, true, func(h statHost) {
			systemdDirs(h)
			h.files["/usr/lib/systemd/system/other.service"] = "[Service]\nExecStart=/usr/local/bin/marker-tool\n"
			h.denied["/usr/lib/systemd/system"] = true
		}, ReasonWebUserWritable},
		{"cron.d not listed", 1, true, func(h statHost) {
			h.files["/etc/cron.d/marker"] = "0 * * * * root /usr/local/bin/marker-tool\n"
			h.denied["/etc/cron.d"] = true
		}, ReasonWebUserWritable},
		{"user manager kept for nginx", 1, true, func(h statHost) {
			h.st["/var/lib/systemd/linger"] = FileStat{Mode: fs.ModeDir | 0o755}
			h.files["/var/lib/systemd/linger/nginx"] = ""
		}, ReasonWebUserWritable},
		{"cron.d line as nginx", 1, true, func(h statHost) {
			h.files["/etc/cron.d/marker"] = "SHELL=/bin/sh\n*/5 * * * * nginx /usr/local/bin/marker-tool\n"
		}, ReasonWebUserWritable},
		{"@daily line as nginx", 1, true, func(h statHost) {
			h.files["/etc/crontab"] = "@daily nginx /usr/local/bin/marker-tool\n"
		}, ReasonWebUserWritable},
		{"nginx's own crontab", 1, true, func(h statHost) {
			h.files["/var/spool/cron/nginx"] = "* * * * * /usr/local/bin/marker-tool\n"
		}, ReasonWebUserWritable},
		{"crontabs not listed", 1, true, func(h statHost) {
			h.denied["/var/spool/cron"] = true
		}, ReasonWebUserWritable},
		{"cron of root and a unit as another account", 1, true, func(h statHost) {
			systemdDirs(h)
			h.files["/etc/passwd"] += "marker:x:1500:1500::/home/marker:/bin/sh\n"
			h.files["/etc/group"] += "marker:x:1500:\n"
			h.files[wants+"/marker.service"] = "[Service]\nUser=marker\nExecStart=/usr/local/bin/marker-tool\n"
			h.files["/etc/cron.d/marker"] = "0 * * * * root /usr/local/bin/marker-tool\n"
		}, ""},
		{"another account with nginx's uid", 1, true, func(h statHost) {
			h.files["/etc/passwd"] += "marker:x:999:1500::/home/marker:/bin/sh\n"
		}, ReasonWebUserWritable},
		{"nginx runs code (njs)", 1, true, func(h statHost) {
			h.files["/etc/nginx/nginx.conf"] = "user nginx;\nload_module modules/ngx_http_js_module.so;\nhttp {\n\taccess_log /var/log/nginx/access.log;\n}\n"
		}, ReasonWebUserWritable},
		{"workers in the pool's group", 1, true, func(h statHost) {
			h.files["/etc/nginx/nginx.conf"] = "user nginx apache;\nhttp {\n\taccess_log /var/log/nginx/access.log;\n}\n"
		}, ReasonWebUserWritable},
		{"no user directive", 1, true, func(h statHost) {
			h.files["/etc/nginx/nginx.conf"] = "http {\n\taccess_log /var/log/nginx/access.log;\n}\n"
		}, ReasonWebUserWritable},
		{"nginx as the shared www-data", 0, false, func(h statHost) {
			h.files["/etc/passwd"] += "www-data:x:33:33::/var/www:/sbin/nologin\n"
			h.files["/etc/group"] += "www-data:x:33:\n"
			h.files["/etc/nginx/nginx.conf"] = "user www-data;\nhttp {\n\taccess_log /var/log/nginx/access.log;\n}\n"
		}, ReasonWebUserWritable},
		{"accounts also from sss", 1, true, func(h statHost) {
			h.files["/etc/nsswitch.conf"] = "passwd: files sss systemd\ngroup: files sss systemd\n"
		}, ReasonWebUserWritable},
		{"group-writable file", 1, true, func(h statHost) {
			h.st["/var/log/nginx/access.log"] = FileStat{Mode: 0o660, UID: 999, GID: intp(0)}
		}, ReasonUntrusted},
	}
	for _, r := range rows {
		h := serverHost(r.ptrace, r.rotated)
		if r.edit != nil {
			r.edit(h)
		}
		s, ok := webLogsByKey(t, LinuxCollector{}.WebLogs(h))[log]
		if !ok {
			t.Errorf("%s: %s not found", r.name, log)
			continue
		}
		if s.Verified != (r.want == "") || s.Reason != r.want {
			t.Errorf("%s: verified %v %q (%s); want %q", r.name, s.Verified, s.Reason, s.Detail, r.want)
		}
		if r.want == "" && r.rotated && s.FileUID != 999 {
			t.Errorf("%s: FileUID %d, want nginx's 999", r.name, s.FileUID)
		}
	}
}

// A configuration file of the server's account is not root's alone: the
// workers are not to change what the server runs.
func TestServerAccountNotForConf(t *testing.T) {
	h := serverHost(1, true)
	h.files["/etc/nginx/conf.d/marker.conf"] = "server {\n\tlisten 8080;\n}\n"
	h.files["/etc/nginx/nginx.conf"] = "user nginx;\nhttp {\n\taccess_log /var/log/nginx/access.log;\n\tinclude /etc/nginx/conf.d/*.conf;\n}\n"
	h.st["/etc/nginx"] = FileStat{Mode: fs.ModeDir | 0o755}
	h.st["/etc/nginx/conf.d"] = FileStat{Mode: fs.ModeDir | 0o755, UID: 999}
	web := LinuxCollector{}.WebAccounts(h)
	if _, ok := web.ServerUIDs["nginx"][999]; !ok {
		t.Fatalf("nginx not a server account: %+v", web.ServerUIDs)
	}
	if why := confTrusted(h, "/etc/nginx/conf.d/marker.conf", WebConf{Root: "/etc"}, web.ForServer("nginx")); why == "" {
		t.Errorf("a configuration directory of nginx's own trusted")
	}
	if r := JudgeLog(h, "/var/log/nginx/access.log", web.ForServer("nginx")); !r.Verified {
		t.Errorf("the log itself: %+v", r)
	}
	// Another server's log, or no server named: root's alone.
	for _, w := range []WebAccounts{web.ForServer("apache"), web} {
		if r := JudgeLog(h, "/var/log/nginx/access.log", w); r.Verified {
			t.Errorf("nginx's file judged for %q: verified", w.judging)
		}
	}
}

func systemdDirs(h statHost) {
	for _, d := range []string{"/etc/systemd", "/etc/systemd/system", "/etc/systemd/system/multi-user.target.wants", "/usr/lib/systemd", "/usr/lib/systemd/system"} {
		h.st[d] = FileStat{Mode: fs.ModeDir | 0o755}
	}
}

func intp(n int) *int { return &n }

// Every module Rocky 9 loads by default is classified: known to run no
// application code, run programs as the children's account, or mod_lua.
func TestRockyModulesClassified(t *testing.T) {
	n := 0
	for _, mods := range rockyHTTPDModules {
		for _, m := range strings.Fields(mods) {
			m += "_module"
			if !apacheSafeModules[m] && !apacheExecModules[m] && m != "lua_module" && m != "remoteip_module" {
				t.Errorf("%s not classified", m)
			}
			n++
		}
	}
	t.Logf("%d modules", n)
}

func TestApacheModulesTrust(t *testing.T) {
	const log = "apache access /etc/httpd/logs/access_log"
	rows := []struct {
		name   string
		ptrace int
		conf   string // added to httpd.conf
		want   Reason
	}{
		{"defaults, ptrace_scope 1", 1, "", ""},
		{"defaults, ptrace_scope 0", 0, "", ReasonWebUserWritable},
		{"a lua-script handler", 1, "<Location /marker>\nSetHandler lua-script\n</Location>\n", ReasonWebUserWritable},
		{"AddHandler lua-script", 1, "AddHandler lua-script .lua\n", ReasonWebUserWritable},
		{"a Lua hook", 1, "LuaHookTranslateName /etc/httpd/marker.lua marker_hook\n", ReasonWebUserWritable},
		{"AllowOverride All", 1, "<Directory /var/www/html>\nAllowOverride All\n</Directory>\n", ReasonWebUserWritable},
		{"AllowOverride FileInfo", 1, "<Directory /var/www/html>\nAllowOverride FileInfo AuthConfig\n</Directory>\n", ReasonWebUserWritable},
		{"AllowOverrideList", 1, "<Directory /var/www/html>\nAllowOverride None\nAllowOverrideList SetHandler\n</Directory>\n", ReasonWebUserWritable},
		{"AllowOverride AuthConfig Indexes", 1, "<Directory /var/www/html>\nAllowOverride AuthConfig Indexes Limit Options=Indexes\n</Directory>\n", ReasonWebUserWritable},
		{"AllowOverride None", 1, "<Directory /var/www/html>\nAllowOverride None\n</Directory>\n", ""},
		{"AddType lua-script", 1, "AddType lua-script .marker\n", ReasonWebUserWritable},
		{"RewriteRule H=lua-script", 1, "RewriteRule ^/marker - [H=lua-script]\n", ReasonWebUserWritable},
		{"mod_cgi", 1, "LoadModule cgi_module modules/mod_cgi.so\n", ReasonWebUserWritable},
		{"mod_php", 1, "LoadModule php_module modules/libphp.so\n", ReasonWebUserWritable},
	}
	for _, r := range rows {
		h := distroHost("rocky9", r.ptrace, false)
		h.files["/etc/httpd/conf/httpd.conf"] += r.conf
		s, ok := webLogsByKey(t, LinuxCollector{}.WebLogs(h))[log]
		if !ok {
			t.Errorf("%s: %s not found", r.name, log)
			continue
		}
		if s.Verified != (r.want == "") || s.Reason != r.want {
			t.Errorf("%s: verified %v %q (%s); want %q", r.name, s.Verified, s.Reason, s.Detail, r.want)
		}
		if r.name == "defaults, ptrace_scope 0" && !strings.Contains(s.Detail, "ptrace_scope=1") {
			t.Errorf("%s: the alert does not say what lets it pass: %s", r.name, s.Detail)
		}
	}
}

// journalHost is Debian 12's nginx (distroHost) sending its access log to
// journald, as shentu's suggested line has it.
func journalHost(ptrace int) statHost {
	h := distroHost("debian12", ptrace, false)
	h.files["/etc/nginx/nginx.conf"] = "user www-data;\nhttp {\n\taccess_log syslog:server=unix:/dev/log,nohostname combined;\n\terror_log /var/log/nginx/error.log;\n}\n"
	for _, d := range []string{"/dev", "/run", "/run/systemd", "/run/systemd/journal", "/usr", "/usr/sbin", "/lib", "/lib/systemd", "/lib/systemd/system"} {
		h.st[d] = FileStat{Mode: fs.ModeDir | 0o755, GID: intp(0)}
	}
	h.links["/dev/log"] = "/run/systemd/journal/dev-log"
	h.files["/run/systemd/journal/dev-log"] = ""
	h.files["/lib/systemd/system/nginx.service"] = "[Service]\nType=forking\nExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on; master_process on;'\nExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'\n"
	h.files["/usr/sbin/nginx"] = ""
	h.st["/usr/sbin/nginx"] = FileStat{Mode: 0o755, GID: intp(0)}
	return h
}

func TestJournalChannel(t *testing.T) {
	const log = "nginx access syslog:server=unix:/dev/log,nohostname"
	rows := []struct {
		name   string
		ptrace int
		edit   func(h statHost)
		want   Reason // "" verified
	}{
		{"suggested line, ptrace_scope 1", 1, nil, ""},
		// www-data is PHP's too: it may ptrace the workers.
		{"ptrace_scope 0", 0, nil, ReasonWebUserWritable},
		{"/dev/log is another daemon's", 1, func(h statHost) {
			h.links["/dev/log"] = "/run/marker-syslog.sock"
			h.files["/run/marker-syslog.sock"] = ""
		}, ReasonUnverified},
		{"no unit", 1, func(h statHost) {
			delete(h.files, "/lib/systemd/system/nginx.service")
		}, ReasonUnverified},
		{"program writable by its group", 1, func(h statHost) {
			h.st["/usr/sbin/nginx"] = FileStat{Mode: 0o775, GID: intp(0)}
		}, ReasonUntrusted},
		{"workers' account not set", 1, func(h statHost) {
			h.files["/etc/nginx/nginx.conf"] = "http {\n\taccess_log syslog:server=unix:/dev/log,nohostname combined;\n}\n"
		}, ReasonUnverified},
		{"client from a header", 1, func(h statHost) {
			h.files["/etc/nginx/nginx.conf"] = "user www-data;\nhttp {\n\tset_real_ip_from 192.0.2.0/24;\n\taccess_log syslog:server=unix:/dev/log,nohostname combined;\n}\n"
		}, ReasonClientFromHeader},
		{"nginx runs code", 1, func(h statHost) {
			h.files["/etc/nginx/nginx.conf"] = "user www-data;\nload_module modules/ngx_http_js_module.so;\nhttp {\n\taccess_log syslog:server=unix:/dev/log,nohostname combined;\n}\n"
		}, ReasonWebUserWritable},
	}
	for _, r := range rows {
		h := journalHost(r.ptrace)
		if r.edit != nil {
			r.edit(h)
		}
		s, ok := webLogsByKey(t, LinuxCollector{}.WebLogs(h))[log]
		if !ok {
			t.Errorf("%s: %s not found among %v", r.name, log, webLogsByKey(t, LinuxCollector{}.WebLogs(h)))
			continue
		}
		if s.Verified != (r.want == "") || (r.want != "" && s.Reason != r.want && !(r.want == ReasonUntrusted && s.Reason == ReasonUnverified)) {
			t.Errorf("%s: verified %v %q (%s); want %q", r.name, s.Verified, s.Reason, s.Detail, r.want)
		}
		if r.want == "" && (s.Journal != "nginx.service" || s.JournalTag != "nginx" || s.JournalExe != "/usr/sbin/nginx" || s.JournalUID != 33) {
			t.Errorf("%s: journal %q tag %q exe %q uid %d", r.name, s.Journal, s.JournalTag, s.JournalExe, s.JournalUID)
		}
	}
	// Without nohostname the hostname comes before the tag: not read as
	// the journal, as any syslog destination.
	h := journalHost(1)
	h.files["/etc/nginx/nginx.conf"] = "user www-data;\nhttp {\n\taccess_log syslog:server=unix:/dev/log combined;\n}\n"
	if s := webLogsByKey(t, LinuxCollector{}.WebLogs(h))["nginx access syslog:server=unix:/dev/log"]; s.Verified || s.Reason != ReasonNotAFile || s.Journal != "" {
		t.Errorf("without nohostname: %+v", s)
	}
}
