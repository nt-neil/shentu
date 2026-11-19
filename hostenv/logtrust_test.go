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
		// Whatever else runs programs as nginx, or its group (review 1, N-1).
		{"supervisord program as nginx", 1, true, func(h statHost) {
			h.files["/etc/supervisord.d/marker.ini"] = "[program:marker]\ncommand=/usr/local/bin/marker-tool\nuser=nginx\n"
		}, ReasonWebUserWritable},
		{"supervisord program as nginx, ptrace_scope 0", 0, true, func(h statHost) {
			h.files["/etc/supervisor/conf.d/marker.conf"] = "[program:marker]\ncommand=/usr/local/bin/marker-tool\nuser = nginx ; marker\n"
		}, ReasonWebUserWritable},
		{"supervisord includes a file elsewhere", 1, true, func(h statHost) {
			h.files["/etc/supervisord.conf"] = "[supervisord]\n[include]\nfiles = /srv/marker/*.conf\n"
			h.files["/srv/marker/a.conf"] = "[program:marker]\ncommand=/usr/local/bin/marker-tool\nuser=nginx\n"
		}, ReasonWebUserWritable},
		{"supervisord program's user from the environment", 1, true, func(h statHost) {
			h.files["/etc/supervisord.d/marker.ini"] = "[program:marker]\ncommand=/usr/local/bin/marker-tool\nuser=%(ENV_MARKER)s\n"
		}, ReasonWebUserWritable},
		{"supervisord user: with a colon", 1, true, func(h statHost) {
			h.files["/etc/supervisord.d/marker.ini"] = "[program:marker]\ncommand: /usr/local/bin/marker-tool\nuser: nginx\n"
		}, ReasonWebUserWritable},
		{"supervisord user on a continuation line", 1, true, func(h statHost) {
			h.files["/etc/supervisord.d/marker.ini"] = "[program:marker]\ncommand=/usr/local/bin/marker-tool\nuser =\n  nginx\n"
		}, ReasonWebUserWritable},
		{"a running supervisord's own configuration", 1, true, func(h statHost) {
			supervisordProc(h, "/usr/bin/python3\x00/usr/local/bin/supervisord\x00-c\x00/srv/marker/sup.conf\x00")
			h.files["/srv/marker/sup.conf"] = "[program:marker]\ncommand=/usr/local/bin/marker-tool\nuser=nginx\n"
		}, ReasonWebUserWritable},
		{"a running supervisord by python's -m, joined", 1, true, func(h statHost) {
			supervisordProc(h, "/usr/bin/python3\x00-msupervisor.supervisord\x00-c\x00/srv/marker/sup.conf\x00")
			h.files["/srv/marker/sup.conf"] = "[program:marker]\ncommand=/usr/local/bin/marker-tool\nuser=nginx\n"
		}, ReasonWebUserWritable},
		{"a running supervisord's configuration by a relative path", 1, true, func(h statHost) {
			supervisordProc(h, "/usr/local/bin/supervisord\x00-c\x00sup.conf\x00")
		}, ReasonWebUserWritable},
		{"a running supervisord, another account", 1, true, func(h statHost) {
			h.files["/etc/passwd"] += "marker:x:1500:1500::/home/marker:/sbin/nologin\n"
			h.files["/etc/group"] += "marker:x:1500:\n"
			supervisordProc(h, "/usr/bin/python3\x00-m\x00supervisor.supervisord\x00-n\x00--configuration=/srv/marker/sup.conf\x00")
			h.files["/srv/marker/sup.conf"] = "[program:marker]\ncommand=/usr/local/bin/marker-tool\nuser=marker\n"
		}, ""},
		{"a running supervisord with no -c", 1, true, func(h statHost) {
			supervisordProc(h, "/opt/marker/bin/supervisord\x00")
		}, ReasonWebUserWritable},
		{"a running supervisord with an option not told", 1, true, func(h statHost) {
			h.files["/etc/passwd"] += "marker:x:1500:1500::/home/marker:/sbin/nologin\n"
			h.files["/etc/group"] += "marker:x:1500:\n"
			supervisordProc(h, "/usr/bin/supervisord\x00-c\x00/srv/marker/sup.conf\x00--marker\x00")
			h.files["/srv/marker/sup.conf"] = "[program:marker]\ncommand=/usr/local/bin/marker-tool\nuser=marker\n"
		}, ReasonWebUserWritable},
		{"a running supervisord under another root", 1, true, func(h statHost) {
			h.files["/etc/passwd"] += "marker:x:1500:1500::/home/marker:/sbin/nologin\n"
			h.files["/etc/group"] += "marker:x:1500:\n"
			supervisordProc(h, "/usr/bin/supervisord\x00-c\x00/srv/marker/sup.conf\x00")
			h.files["/srv/marker/sup.conf"] = "[program:marker]\ncommand=/usr/local/bin/marker-tool\nuser=marker\n"
			h.links["/proc/4400/root"] = "/srv/marker-root"
		}, ReasonWebUserWritable},
		{"a running supervisord in another mount namespace", 1, true, func(h statHost) {
			h.files["/etc/passwd"] += "marker:x:1500:1500::/home/marker:/sbin/nologin\n"
			h.files["/etc/group"] += "marker:x:1500:\n"
			supervisordProc(h, "/usr/bin/supervisord\x00-c\x00/srv/marker/sup.conf\x00")
			h.files["/srv/marker/sup.conf"] = "[program:marker]\ncommand=/usr/local/bin/marker-tool\nuser=marker\n"
			h.links["/proc/4400/ns/mnt"] = "mnt:[4026532000]"
		}, ReasonWebUserWritable},
		{"an indented supervisord line", 1, true, func(h statHost) {
			h.files["/etc/supervisord.d/marker.ini"] = "[program:marker]\n  user=nginx\ncommand=/usr/local/bin/marker-tool\n"
		}, ReasonWebUserWritable},
		{"an indented supervisord line, not told", 1, true, func(h statHost) {
			h.files["/etc/passwd"] += "marker:x:1500:1500::/home/marker:/sbin/nologin\n"
			h.files["/etc/group"] += "marker:x:1500:\n"
			h.files["/etc/supervisord.d/marker.ini"] = "[program:marker]\nuser=marker\ncommand=/usr/local/bin/marker-tool\n  --marker=a\n"
		}, ReasonWebUserWritable},
		{"supervisord programs not listed", 1, true, func(h statHost) {
			h.files["/etc/supervisord.d/marker.ini"] = "[program:marker]\ncommand=/usr/local/bin/marker-tool\n"
			h.denied["/etc/supervisord.d"] = true
		}, ReasonWebUserWritable},
		{"supervisord program as another account", 1, true, func(h statHost) {
			h.files["/etc/passwd"] += "marker:x:1500:1500::/home/marker:/sbin/nologin\n"
			h.files["/etc/group"] += "marker:x:1500:\n"
			h.files["/etc/supervisord.d/marker.ini"] = "[program:marker]\ncommand=/usr/local/bin/marker-tool\nuser=marker\n"
		}, ""},
		{"supervisord user: another account, with a colon", 1, true, func(h statHost) {
			h.files["/etc/passwd"] += "marker:x:1500:1500::/home/marker:/sbin/nologin\n"
			h.files["/etc/group"] += "marker:x:1500:\n"
			h.files["/etc/supervisord.d/marker.ini"] = "[program:marker]\ncommand: /usr/local/bin/marker-tool\nuser: marker\n"
		}, ""},
		{"sudo runs commands as nginx", 1, true, func(h statHost) {
			h.files["/etc/sudoers"] = "root ALL=(ALL) ALL\n#includedir /etc/sudoers.d\n"
			h.files["/etc/sudoers.d/marker"] = "marker ALL=(nginx) NOPASSWD: ALL\n"
		}, ReasonWebUserWritable},
		{"sudo runs commands as nginx by uid", 1, true, func(h statHost) {
			h.files["/etc/sudoers"] = "marker ALL=(#999) /usr/local/bin/marker-tool\n"
		}, ReasonWebUserWritable},
		{"sudo runs commands with nginx's group", 1, true, func(h statHost) {
			h.files["/etc/sudoers"] = "@includedir /etc/sudoers.d\n"
			h.files["/etc/sudoers.d/marker"] = "marker ALL=(root : nginx) /usr/local/bin/marker-tool\n"
		}, ReasonWebUserWritable},
		{"sudo's Runas_Alias names nginx", 1, true, func(h statHost) {
			h.files["/etc/sudoers"] = "Runas_Alias MARKER = nginx\nmarker ALL=(MARKER) /usr/local/bin/marker-tool\n"
		}, ReasonWebUserWritable},
		{"sudo runs some commands as anyone", 1, true, func(h statHost) {
			h.files["/etc/sudoers"] = "marker ALL=(ALL) NOPASSWD: /usr/local/bin/marker-tool\n"
		}, ReasonWebUserWritable},
		{"sudoers.d not listed", 1, true, func(h statHost) {
			h.files["/etc/sudoers"] = "#includedir /etc/sudoers.d\n"
			h.files["/etc/sudoers.d/marker"] = "marker ALL=(root) /usr/local/bin/marker-tool\n"
			h.denied["/etc/sudoers.d"] = true
		}, ReasonWebUserWritable},
		{"sudoers unread", 1, true, func(h statHost) {
			h.files["/etc/sudoers"] = "root ALL=(ALL) ALL\n"
			h.denied["/etc/sudoers"] = true
		}, ReasonWebUserWritable},
		{"sudoers also from sss", 1, true, func(h statHost) {
			h.files["/etc/nsswitch.conf"] = "passwd: files systemd\ngroup: files systemd\nsudoers: files sss\n"
		}, ReasonWebUserWritable},
		{"the distribution's sudoers", 1, true, func(h statHost) {
			h.files["/etc/sudoers"] = "## Allow root to run any commands anywhere\nDefaults    secure_path = /sbin:/bin:/usr/sbin:/usr/bin\nroot\tALL=(ALL) \tALL\n%wheel\tALL=(ALL)\tALL\n%sudo ALL=(ALL:ALL) ALL\n#includedir /etc/sudoers.d\n"
			h.files["/etc/sudoers.d/marker"] = "marker ALL=(root) NOPASSWD: /usr/local/bin/marker-tool\n"
		}, ""},
		// Review 2, S-1..S-3.
		{"supervisord's [include] with a comment after it", 1, true, func(h statHost) {
			h.files["/etc/supervisord.conf"] = "[supervisord]\n[include] ; marker\nfiles = /srv/marker/*.conf\n"
			h.files["/srv/marker/a.conf"] = "[program:marker]\ncommand=/usr/local/bin/marker-tool\nuser=nginx\n"
		}, ReasonWebUserWritable},
		{"doas runs commands as nginx", 1, true, func(h statHost) {
			h.files["/etc/doas.conf"] = "permit persist :wheel\npermit nopass marker as nginx cmd /usr/local/bin/marker-tool\n"
		}, ReasonWebUserWritable},
		{"doas as nginx past a setenv block", 1, true, func(h statHost) {
			h.files["/etc/doas.conf"] = "permit setenv { PATH MARKER=1 } marker as nginx\n"
		}, ReasonWebUserWritable},
		{"doas rule not told", 1, true, func(h statHost) {
			h.files["/etc/doas.conf"] = "allow marker as nginx\n"
		}, ReasonWebUserWritable},
		{"doas rule quoted", 1, true, func(h statHost) {
			h.files["/etc/doas.conf"] = "permit marker as \"nginx\"\n"
		}, ReasonWebUserWritable},
		{"doas.conf unread", 1, true, func(h statHost) {
			h.files["/etc/doas.conf"] = "permit persist :wheel\n"
			h.denied["/etc/doas.conf"] = true
		}, ReasonWebUserWritable},
		{"doas only as root", 1, true, func(h statHost) {
			h.files["/etc/doas.conf"] = "# marker\npermit persist :wheel\npermit nopass marker cmd /usr/local/bin/marker-tool\ndeny marker as nginx\n"
		}, ""},
		{"sudo as anyone but root", 1, true, func(h statHost) {
			h.files["/etc/sudoers"] = "marker ALL=(ALL, !root) ALL\n"
		}, ReasonWebUserWritable},
		{"sudo with any group but one", 1, true, func(h statHost) {
			h.files["/etc/sudoers"] = "marker ALL=(root : ALL, !wheel) ALL\n"
		}, ReasonWebUserWritable},
		// Ubuntu VM acceptance (21598e8): cloud-init's sudoers line, and the
		// units Ubuntu's packages mask.
		{"cloud-init's sudoers line", 0, true, func(h statHost) {
			h.files["/etc/sudoers"] = "@includedir /etc/sudoers.d\n"
			h.files["/etc/sudoers.d/90-cloud-init-users"] = "# Created by cloud-init v. 24.4 on Thu, 19 Nov 2026 13:02:11 +0000\n\n# User rules for admin\nadmin ALL=(ALL) NOPASSWD:ALL\n"
		}, ""},
		{"tags run together before ALL", 1, true, func(h statHost) {
			h.files["/etc/sudoers"] = "admin ALL=(ALL:ALL) NOPASSWD:SETENV: ALL\n"
		}, ""},
		{"tags run together before some commands", 1, true, func(h statHost) {
			h.files["/etc/sudoers"] = "marker ALL=(ALL) NOPASSWD:SETENV:/usr/local/bin/marker-tool\n"
		}, ReasonWebUserWritable},
		{"a tag not known before ALL", 1, true, func(h statHost) {
			h.files["/etc/sudoers"] = "marker ALL=(ALL) MARKERTAG:ALL\n"
		}, ReasonWebUserWritable},
		{"an option before ALL", 1, true, func(h statHost) {
			h.files["/etc/sudoers"] = "marker ALL=(ALL) CWD=/srv ALL\n"
		}, ReasonWebUserWritable},
		{"units Ubuntu's packages mask", 0, true, func(h statHost) {
			systemdDirs(h)
			h.st["/dev/null"] = FileStat{Mode: fs.ModeDevice | fs.ModeCharDevice | 0o666}
			for _, u := range []string{"cryptdisks-early", "cryptdisks", "hwclock", "multipath-tools-boot", "screen-cleanup", "sudo", "x11-common"} {
				h.links["/usr/lib/systemd/system/"+u+".service"] = "/dev/null"
			}
			h.files["/usr/lib/systemd/system/marker.service"] = "[Service]\nExecStart=/usr/local/bin/marker-tool\n"
		}, ""},
		{"a masked unit's drop-in names nginx", 1, true, func(h statHost) {
			systemdDirs(h)
			h.st["/dev/null"] = FileStat{Mode: fs.ModeDevice | fs.ModeCharDevice | 0o666}
			h.links["/etc/systemd/system/marker.service"] = "/dev/null"
			h.files["/usr/lib/systemd/system/marker.service"] = "[Service]\nExecStart=/usr/local/bin/marker-tool\n"
			h.st["/etc/systemd/system/marker.service.d"] = FileStat{Mode: fs.ModeDir | 0o755}
			h.files["/etc/systemd/system/marker.service.d/user.conf"] = "[Service]\nUser=nginx\n"
		}, ""},
		{"a unit linked to another device", 1, true, func(h statHost) {
			systemdDirs(h)
			h.st["/dev/zero"] = FileStat{Mode: fs.ModeDevice | fs.ModeCharDevice | 0o666}
			h.links["/usr/lib/systemd/system/marker.service"] = "/dev/zero"
		}, ReasonWebUserWritable},
		{"nginx has a login shell", 1, true, func(h statHost) {
			h.files["/etc/passwd"] = strings.Replace(h.files["/etc/passwd"], "/var/lib/nginx:/sbin/nologin", "/var/lib/nginx:/bin/bash", 1)
		}, ReasonWebUserWritable},
		{"a program runs as nginx now", 1, true, func(h statHost) {
			nginxProcs(h)
			h.files["/proc/4300/status"] = "Name:\tnginx\nUid:\t999\t999\t999\t999\nGid:\t996\t996\t996\t996\nGroups:\t996\n"
			h.links["/proc/4300/exe"] = "/usr/local/bin/marker-tool"
		}, ReasonWebUserWritable},
		{"a program runs with nginx's group now", 0, true, func(h statHost) {
			nginxProcs(h)
			h.files["/proc/4300/status"] = "Name:\tmarker\nUid:\t1500\t1500\t1500\t1500\nGid:\t1500\t1500\t1500\t1500\nGroups:\t996 1500\n"
			h.links["/proc/4300/exe"] = "/usr/local/bin/marker-tool"
		}, ReasonWebUserWritable},
		{"nginx's program from a file not root's", 1, true, func(h statHost) {
			nginxProcs(h)
			h.st["/usr/sbin/nginx"] = FileStat{Mode: 0o755, UID: 999, GID: intp(0)}
		}, ReasonWebUserWritable},
		{"a worker of a deleted (upgraded) nginx", 1, true, func(h statHost) {
			nginxProcs(h)
			h.links["/proc/4201/exe"] = "/usr/sbin/nginx (deleted)"
		}, ReasonWebUserWritable},
		{"a process's program not read", 1, true, func(h statHost) {
			nginxProcs(h)
			delete(h.links, "/proc/4201/exe")
		}, ReasonWebUserWritable},
		{"/proc not listed", 1, true, func(h statHost) {
			nginxProcs(h)
			h.denied["/proc"] = true
		}, ReasonWebUserWritable},
		{"nginx's master and worker, another account's program", 0, true, func(h statHost) {
			nginxProcs(h)
			h.files["/etc/passwd"] += "marker:x:1500:1500::/home/marker:/sbin/nologin\n"
			h.files["/etc/group"] += "marker:x:1500:\n"
			h.files["/proc/4300/status"] = "Name:\tmarker\nUid:\t1500\t1500\t1500\t1500\nGid:\t1500\t1500\t1500\t1500\nGroups:\t1500\n"
			h.links["/proc/4300/exe"] = "/usr/local/bin/marker-tool"
		}, ""},
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

// supervisordProc: a supervisord running as pid 4400 with argv, in the
// host's root and mount namespace.
func supervisordProc(h statHost, argv string) {
	h.files["/proc/4400/cmdline"] = argv
	h.links["/proc/4400/root"] = "/"
	h.links["/proc/4400/ns/mnt"] = "mnt:[4026531841]"
	h.links["/proc/1/ns/mnt"] = "mnt:[4026531841]"
}

// nginxProcs: nginx's root master and one worker as nginx, running the
// root-owned /usr/sbin/nginx.
func nginxProcs(h statHost) {
	h.files["/proc/4200/status"] = "Name:\tnginx\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t\n"
	h.links["/proc/4200/exe"] = "/usr/sbin/nginx"
	h.files["/proc/4201/status"] = "Name:\tnginx\nUid:\t999\t999\t999\t999\nGid:\t996\t996\t996\t996\nGroups:\t996\n"
	h.links["/proc/4201/exe"] = "/usr/sbin/nginx"
	h.files["/usr/sbin/nginx"] = ""
	h.st["/usr/sbin/nginx"] = FileStat{Mode: 0o755, GID: intp(0)}
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

// RewriteMap prg: runs a program as the children's account, as the exec
// modules do: under ptrace_scope 0 it may trace the children, and the alert
// names it (review 1, S-1). (apache is a shared account: never apart.)
func TestApacheRewriteMapPrg(t *testing.T) {
	const log = "apache access /etc/httpd/logs/access_log"
	for _, r := range []struct {
		name, conf string
		named      bool
	}{
		{"no exec module", "", false},
		{"RewriteMap prg:", "RewriteMap marker \"prg:/usr/local/bin/marker-map\"\n", true},
		{"RewriteMap txt:", "RewriteMap marker \"txt:/etc/httpd/marker.map\"\n", false},
	} {
		h := distroHost("rocky9", 0, false)
		h.files["/etc/nsswitch.conf"] = "passwd: files systemd\ngroup: files systemd\n"
		base := h.files["/etc/httpd/conf.modules.d/00-base.conf"]
		for _, m := range []string{"actions", "ext_filter", "include", "suexec", "userdir"} {
			base = strings.Replace(base, "LoadModule "+m+"_module modules/mod_"+m+".so\n", "", 1)
		}
		h.files["/etc/httpd/conf.modules.d/00-base.conf"] = base
		h.files["/etc/httpd/conf/httpd.conf"] += r.conf
		s, ok := webLogsByKey(t, LinuxCollector{}.WebLogs(h))[log]
		if !ok {
			t.Fatalf("%s: %s not found", r.name, log)
		}
		if s.Verified || s.Reason != ReasonWebUserWritable {
			t.Errorf("%s: verified %v %q (%s); want web_user_writable", r.name, s.Verified, s.Reason, s.Detail)
		}
		if strings.Contains(s.Detail, "RewriteMap prg:") != r.named || strings.Contains(s.Detail, "_module") {
			t.Errorf("%s: alert %q; RewriteMap prg: named should be %v, no module", r.name, s.Detail, r.named)
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
		{"error log under the same tag", 1, func(h statHost) {
			h.files["/etc/nginx/nginx.conf"] = "user www-data;\nerror_log syslog:server=unix:/dev/log,nohostname;\nhttp {\n\taccess_log syslog:server=unix:/dev/log,nohostname combined;\n}\n"
		}, ReasonUnverified},
		{"another access log format, same tag", 1, func(h statHost) {
			h.files["/etc/nginx/nginx.conf"] = "user www-data;\nhttp {\n\tlog_format marker '$remote_addr $request';\n\taccess_log syslog:server=unix:/dev/log,nohostname combined;\n\tserver {\n\t\tserver_name a.example;\n\t}\n\tserver {\n\t\tserver_name b.example;\n\t\taccess_log syslog:server=unix:/dev/log,nohostname,severity=info marker;\n\t}\n}\n"
		}, ReasonUnverified},
		{"a stream block's log under the same tag", 1, func(h statHost) {
			h.files["/etc/nginx/nginx.conf"] = "user www-data;\nstream {\n\tlog_format basic '$remote_addr';\n\taccess_log syslog:server=unix:/dev/log,nohostname basic;\n\tserver {\n\t\tlisten 9000;\n\t}\n}\nhttp {\n\taccess_log syslog:server=unix:/dev/log,nohostname combined;\n}\n"
		}, ReasonUnverified},
		{"a stream log of the same text", 1, func(h statHost) {
			h.files["/etc/nginx/nginx.conf"] = "user www-data;\nstream {\n\tlog_format combined '$remote_addr';\n\taccess_log syslog:server=unix:/dev/log,nohostname combined;\n}\nhttp {\n\taccess_log syslog:server=unix:/dev/log,nohostname combined;\n}\n"
		}, ReasonUnverified},
		{"the same line in two servers", 1, func(h statHost) {
			h.files["/etc/nginx/nginx.conf"] = "user www-data;\nhttp {\n\tserver {\n\t\tserver_name a.example;\n\t\taccess_log syslog:server=unix:/dev/log,nohostname combined;\n\t}\n\tserver {\n\t\tserver_name b.example;\n\t\taccess_log syslog:server=unix:/dev/log,nohostname combined;\n\t}\n}\n"
		}, ""},
		{"a location's error log under the same tag", 1, func(h statHost) {
			h.files["/etc/nginx/nginx.conf"] = "user www-data;\nhttp {\n\taccess_log syslog:server=unix:/dev/log,nohostname combined;\n\tserver {\n\t\tlocation /m {\n\t\t\terror_log syslog:server=unix:/dev/log,nohostname;\n\t\t}\n\t}\n}\n"
		}, ReasonUnverified},
		{"error log under its own tag", 1, func(h statHost) {
			h.files["/etc/nginx/nginx.conf"] = "user www-data;\nerror_log syslog:server=unix:/dev/log,nohostname,tag=nginx_error;\nhttp {\n\taccess_log syslog:server=unix:/dev/log,nohostname combined;\n}\n"
		}, ""},
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
