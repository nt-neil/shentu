package hostenv

import (
	"io/fs"
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
	if _, ok := web.ServerUIDs[999]; !ok {
		t.Fatalf("nginx not a server account: %+v", web.ServerUIDs)
	}
	if why := confTrusted(h, "/etc/nginx/conf.d/marker.conf", WebConf{Root: "/etc"}, web); why == "" {
		t.Errorf("a configuration directory of nginx's own trusted")
	}
	if r := JudgeLog(h, "/var/log/nginx/access.log", web); !r.Verified {
		t.Errorf("the log itself: %+v", r)
	}
}

func intp(n int) *int { return &n }
