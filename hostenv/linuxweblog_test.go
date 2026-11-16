package hostenv

import (
	"io/fs"
	"strings"
	"testing"
)

// logHost is a Debian-like host with nginx, Apache and PHP-FPM, their logs
// laid out as the distribution's logrotate leaves them.
func logHost() statHost {
	h := statHost{fakeHost: newFake(true), st: map[string]FileStat{}}
	h.files["/etc/passwd"] = "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbob:x:1000:1000::/home/bob:/bin/bash\n"
	dir := FileStat{Mode: fs.ModeDir | 0o755, UID: 0}
	for _, d := range []string{"/", "/var", "/var/log", "/var/log/nginx", "/var/log/apache2", "/var/log/php-fpm"} {
		h.st[d] = dir
	}
	syslog := 104
	h.st["/var/log"] = FileStat{Mode: fs.ModeDir | 0o775, UID: 0, GID: &syslog} // Ubuntu: group syslog may write
	h.files["/etc/group"] = "root:x:0:\nadm:x:4:syslog\nwww-data:x:33:\nsyslog:x:104:\n"
	root := FileStat{Mode: 0o640, UID: 0}
	www := FileStat{Mode: 0o640, UID: 33}

	h.files["/etc/nginx/nginx.conf"] = `user www-data;
error_log /var/log/nginx/error.log;
http {
	log_format main escape=json '{"ip":"$remote_addr",'
		'"req":"$request"}';
	access_log /var/log/nginx/access.log;
	include /etc/nginx/sites-enabled/*;
}
`
	h.files["/etc/nginx/sites-enabled/shop"] = `server {
	server_name shop.test www.shop.test;
	access_log /var/log/nginx/shop.access.log main;  # its own
	location /health { access_log off; }
}
server {
	server_name _;
}
`
	h.files["/var/log/nginx/access.log"], h.st["/var/log/nginx/access.log"] = "", www
	h.files["/var/log/nginx/error.log"], h.st["/var/log/nginx/error.log"] = "", www
	h.files["/var/log/nginx/shop.access.log"], h.st["/var/log/nginx/shop.access.log"] = "", root

	h.files["/etc/apache2/apache2.conf"] = `ErrorLog ${APACHE_LOG_DIR}/error.log
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
<IfModule log_config_module>
	LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O" \
		vhost_combined
</IfModule>
IncludeOptional sites-enabled/*.conf
`
	h.files["/etc/apache2/envvars"] = "export APACHE_RUN_USER=www-data\nexport APACHE_LOG_DIR=/var/log/apache2$SUFFIX\n"
	h.files["/etc/apache2/sites-enabled/a.conf"] = `<VirtualHost *:80>
	ServerName a.test
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
<VirtualHost *:8080>
	ServerName b.test
	CustomLog "|/usr/bin/rotatelogs /var/log/apache2/b.%Y 86400" vhost_combined
	ErrorLog ${UNSET}/b.error.log
</VirtualHost>
`
	h.files["/var/log/apache2/access.log"], h.st["/var/log/apache2/access.log"] = "", root
	h.files["/var/log/apache2/error.log"], h.st["/var/log/apache2/error.log"] = "", root

	h.files["/etc/php/8.2/fpm/php-fpm.conf"] = "[global]\nerror_log = /var/log/php8.2-fpm.log\ninclude=/etc/php/8.2/fpm/pool.d/*.conf\n"
	h.files["/etc/php/8.2/fpm/pool.d/www.conf"] = "[www]\nuser = www-data\nslowlog = /var/log/php-fpm/$pool.slow.log\nphp_admin_value[error_log] = /var/log/php-fpm/www-error.log\n"
	h.files["/var/log/php8.2-fpm.log"], h.st["/var/log/php8.2-fpm.log"] = "", root
	h.files["/var/log/php-fpm/www-error.log"], h.st["/var/log/php-fpm/www-error.log"] = "", www
	return h
}

func webLogsByKey(t *testing.T, o Obs[[]LogSource]) map[string]LogSource {
	t.Helper()
	m := map[string]LogSource{}
	for _, s := range o.Value {
		m[s.Server+" "+s.Kind+" "+s.Path] = s
	}
	return m
}

func TestWebLogsNginx(t *testing.T) {
	o := LinuxCollector{}.WebLogs(logHost())
	if o.Status != StatusOK {
		t.Fatalf("status %s %s: %s", o.Status, o.Reason, o.Detail)
	}
	m := webLogsByKey(t, o)
	shop := m["nginx access /var/log/nginx/shop.access.log"]
	if !shop.Verified || shop.Format != "main" || shop.Escape != "json" || shop.Spec != `{"ip":"$remote_addr","req":"$request"}` ||
		strings.Join(shop.Vhosts, ",") != "shop.test,www.shop.test" || shop.Config != "/etc/nginx/sites-enabled/shop:3" {
		t.Errorf("shop's own access log %+v", shop)
	}
	// The second server has no access_log: the http block's, in combined.
	acc := m["nginx access /var/log/nginx/access.log"]
	if acc.Verified || acc.Reason != ReasonWebUserWritable || acc.Format != "combined" || acc.Spec != ngxCombined ||
		!strings.Contains(acc.Detail, "www-data") || !strings.Contains(acc.Detail, WebUserWritableMeaning) {
		t.Errorf("inherited access log %+v: want web_user_writable, combined", acc)
	}
	if off := m["nginx access off"]; off.Reason != ReasonLoggingDisabled || off.Verified {
		t.Errorf("access_log off %+v", off)
	}
	if e := m["nginx error /var/log/nginx/error.log"]; e.Reason != ReasonWebUserWritable {
		t.Errorf("error log %+v", e)
	}
}

func TestWebLogsApache(t *testing.T) {
	m := webLogsByKey(t, LinuxCollector{}.WebLogs(logHost()))
	a := m["apache access /var/log/apache2/access.log"]
	if !a.Verified || a.Format != "combined" || !strings.HasPrefix(a.Spec, `%h %l %u %t "%r" %>s %O "%{Referer}i"`) || strings.Join(a.Vhosts, ",") != "a.test" {
		t.Errorf("vhost access log %+v", a)
	}
	// b.test names its error log with a variable nothing defines.
	if e := m["apache error ${UNSET}/b.error.log"]; e.Reason != ReasonVariablePath || e.Verified {
		t.Errorf("variable path %+v", e)
	}
	// The main server's error log, written by a.test too (no ErrorLog of its own).
	if e := m["apache error /var/log/apache2/error.log"]; !e.Verified || strings.Join(e.Vhosts, ",") != "a.test" || e.Config != "/etc/apache2/apache2.conf:1" {
		t.Errorf("main error log %+v", e)
	}
	var pipe LogSource
	for k, s := range m {
		if strings.HasPrefix(k, "apache access |") {
			pipe = s
		}
	}
	if pipe.Reason != ReasonNotAFile || pipe.Format != "vhost_combined" || pipe.Spec != `%v:%p %h %l %u %t "%r" %>s %O` {
		t.Errorf("piped log %+v: want not_a_file with the continued LogFormat", pipe)
	}
}

func TestWebLogsPHPFPM(t *testing.T) {
	m := webLogsByKey(t, LinuxCollector{}.WebLogs(logHost()))
	if e := m["php-fpm error /var/log/php8.2-fpm.log"]; !e.Verified {
		t.Errorf("master log %+v", e)
	}
	if e := m["php-fpm php_error /var/log/php-fpm/www-error.log"]; e.Reason != ReasonWebUserWritable || strings.Join(e.Vhosts, ",") != "pool www" {
		t.Errorf("pool's PHP error log %+v", e)
	}
	if e := m["php-fpm slow /var/log/php-fpm/www.slow.log"]; e.Reason != ReasonNotFound {
		t.Errorf("slowlog, $pool expanded, not written yet: %+v", e)
	}
}

// What only root may write, and what else: owner, mode, directories, links.
func TestLogTrust(t *testing.T) {
	h := logHost()
	web := WebAccounts{UIDs: map[int]string{33: "www-data"}, GIDs: map[int]string{33: "www-data"}}
	gid := func(n int) *int { return &n }
	h.st["/var/log/wwwgrp"] = FileStat{Mode: fs.ModeDir | 0o775, UID: 0, GID: gid(33)}
	h.files["/var/log/wwwgrp/a.log"], h.st["/var/log/wwwgrp/a.log"] = "", FileStat{Mode: 0o640, UID: 0}
	h.st["/var/log/sysgrp"] = FileStat{Mode: fs.ModeDir | 0o775, UID: 0, GID: gid(104)}
	h.files["/var/log/sysgrp/a.log"], h.st["/var/log/sysgrp/a.log"] = "", FileStat{Mode: 0o640, UID: 0}
	h.st["/var/log/nogid"] = FileStat{Mode: fs.ModeDir | 0o775, UID: 0}
	h.files["/var/log/nogid/a.log"], h.st["/var/log/nogid/a.log"] = "", FileStat{Mode: 0o640, UID: 0}
	// A chain: the link in bob's directory points on to a trusted file;
	// bob may repoint it.
	h.links["/var/log/nginx/chain.log"] = "/home/bob/hop.log"
	h.links["/home/bob/hop.log"] = "/var/log/nginx/shop.access.log"
	h.files["/var/log/x.log"], h.st["/var/log/x.log"] = "", FileStat{Mode: 0o660, UID: 0}
	h.files["/var/log/bob.log"], h.st["/var/log/bob.log"] = "", FileStat{Mode: 0o640, UID: 1000}
	h.st["/var/log/open"] = FileStat{Mode: fs.ModeDir | 0o777, UID: 0}
	h.files["/var/log/open/a.log"], h.st["/var/log/open/a.log"] = "", FileStat{Mode: 0o640, UID: 0}
	h.st["/var/log/tmp"] = FileStat{Mode: fs.ModeDir | fs.ModeSticky | 0o777, UID: 0}
	h.files["/var/log/tmp/a.log"], h.st["/var/log/tmp/a.log"] = "", FileStat{Mode: 0o640, UID: 0}
	h.st["/home"], h.st["/home/bob"] = FileStat{Mode: fs.ModeDir | 0o755, UID: 0}, FileStat{Mode: fs.ModeDir | 0o755, UID: 1000}
	h.files["/home/bob/real.log"], h.st["/home/bob/real.log"] = "", FileStat{Mode: 0o640, UID: 0}
	h.links["/var/log/nginx/link.log"] = "/home/bob/real.log"
	for p, want := range map[string]Reason{
		"/var/log/nginx/shop.access.log": "",
		"/var/log/nginx/access.log":      ReasonWebUserWritable,
		"/var/log/x.log":                 ReasonUntrusted,
		"/var/log/bob.log":               ReasonUntrusted,
		"/var/log/open/a.log":            ReasonUntrusted,
		"/var/log/tmp/a.log":             "",
		"/var/log/nginx/link.log":        ReasonUntrusted, // a root file, in bob's directory
		"/var/log/nginx/gone.log":        ReasonNotFound,
		"/var/log/wwwgrp/a.log":          ReasonWebUserWritable, // 775 root:www-data: the web user may swap the file
		"/var/log/sysgrp/a.log":          "",                    // 775 root:syslog, as Ubuntu's /var/log
		"/var/log/nogid/a.log":           ReasonUnverified,      // group-writable, group unknown
		"/var/log/nginx/chain.log":       ReasonUntrusted,
	} {
		ok, why, detail := LogTrust(h, p, web)
		if why != want || ok != (want == "") {
			t.Errorf("%s: verified %v, %q (%s); want %q", p, ok, why, detail, want)
		}
	}
}

// Includes are bounded: a file including itself stops at the depth limit
// and says so, not loop.
func TestWebLogsIncludeLoop(t *testing.T) {
	h := statHost{fakeHost: newFake(true), st: map[string]FileStat{}}
	h.files["/etc/nginx/nginx.conf"] = "http { include /etc/nginx/loop.conf; }\n"
	h.files["/etc/nginx/loop.conf"] = "include /etc/nginx/loop.conf;\naccess_log /var/log/nginx/a.log;\n"
	o := LinuxCollector{}.WebLogs(h)
	if o.Status != StatusPartial || !strings.Contains(o.Detail, "deep") {
		t.Errorf("status %s, detail %q: want partial, the depth named", o.Status, o.Detail)
	}
}

// A configuration file that cannot be read makes the result partial,
// never a clean empty list.
func TestWebLogsUnreadable(t *testing.T) {
	h := logHost()
	h.denied["/etc/nginx/sites-enabled/shop"] = true
	o := LinuxCollector{}.WebLogs(h)
	if o.Status != StatusPartial || !strings.Contains(o.Detail, "/etc/nginx/sites-enabled/shop") {
		t.Errorf("status %s, detail %q", o.Status, o.Detail)
	}
}

// A group a web user is a member of (not only its primary group), and a
// user or group given by number, are the web server's too.
func TestWebAccountsMembersAndNumbers(t *testing.T) {
	h := logHost()
	h.files["/etc/group"] = "root:x:0:\nadm:x:4:syslog,www-data\nwww-data:x:33:\nsyslog:x:104:\n"
	h.files["/etc/apache2/apache2.conf"] += "User #48\nGroup 49\n"
	l := &logLoader{src: h, conf: DefaultWebConf, out: map[string]*LogSource{}}
	l.nginx()
	l.apache()
	w := l.webAccounts()
	if w.GIDs[4] != "adm" || w.UIDs[48] == "" || w.GIDs[49] == "" || w.GIDs[104] != "" {
		t.Errorf("accounts %+v: want adm (a member is www-data), uid 48, gid 49, and not syslog", w)
	}
	four := 4
	h.st["/var/log/admgrp"] = FileStat{Mode: fs.ModeDir | 0o775, UID: 0, GID: &four}
	h.files["/var/log/admgrp/a.log"], h.st["/var/log/admgrp/a.log"] = "", FileStat{Mode: 0o640, UID: 0}
	if _, why, _ := LogTrust(h, "/var/log/admgrp/a.log", w); why != ReasonWebUserWritable {
		t.Errorf("775 root:adm with www-data in adm: %q, want web_user_writable", why)
	}
}

// A user given by number brings its primary group and its memberships, as
// one given by name does.
func TestWebAccountsNumericUserGroups(t *testing.T) {
	h := logHost()
	h.files["/etc/passwd"] += "web2:x:2000:2001::/srv:/usr/sbin/nologin\n"
	h.files["/etc/group"] += "web2grp:x:2001:\nshared:x:2002:web2\n"
	h.files["/etc/apache2/apache2.conf"] += "User #2000\n"
	w := LinuxCollector{}.WebAccounts(h)
	if w.UIDs[2000] == "" || w.GIDs[2001] != "web2grp" || w.GIDs[2002] != "shared" {
		t.Errorf("accounts %+v: want uid 2000 with its primary group web2grp and its group shared", w)
	}
}
