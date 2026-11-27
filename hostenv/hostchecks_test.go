package hostenv

import (
	"slices"
	"strings"
	"testing"
)

// I-10: sudoers' rules that run commands with no password, through every
// include sudo reads; a file not read is said, never taken for none.
func TestSudoNopasswd(t *testing.T) {
	h := newFake(true)
	h.files["/etc/sudoers"] = "Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n# ops ALL=(ALL) NOPASSWD: ALL\n@includedir /etc/sudoers.d\n#include extra\n"
	h.files["/etc/sudoers.d/90-cloud-init-users"] = "# made by cloud-init\nadmin ALL=(ALL) NOPASSWD:ALL\n"
	h.files["/etc/sudoers.d/deploy"] = "deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart app, \\\n  /usr/bin/systemctl reload app\n"
	h.files["/etc/sudoers.d/README"] = "ops ALL=(ALL) NOPASSWD: ALL\n"    // no dot, read
	h.files["/etc/sudoers.d/old.bak"] = "ghost ALL=(ALL) NOPASSWD: ALL\n" // a dot: sudo skips it
	h.files["/etc/sudoers.d/vim~"] = "ghost2 ALL=(ALL) NOPASSWD: ALL\n"   // ends in ~: skipped
	h.files["/etc/extra"] = "Defaults:backup !authenticate\n"
	s := SudoNopasswd(h)
	var got []string
	all := false
	for _, r := range s.Rules {
		got = append(got, r.String())
		all = all || r.All
	}
	want := []string{
		"/etc/sudoers.d/90-cloud-init-users: admin ALL=(ALL) NOPASSWD:ALL",
		"/etc/sudoers.d/README: ops ALL=(ALL) NOPASSWD: ALL",
		"/etc/sudoers.d/deploy: deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart app,    /usr/bin/systemctl reload app",
		"/etc/extra: Defaults:backup !authenticate",
	}
	if !slices.Equal(got, want) || !all || len(s.Unread) != 0 {
		t.Errorf("rules %q all %v unread %q", got, all, s.Unread)
	}
	// Who each is for, what it runs, as whom; no cloud.cfg: no default user.
	if r := s.Rules[0]; r.Who != "admin" || !r.All || r.CloudDefault || !r.OneUser() || !slices.Equal(r.Runas, []string{"ALL"}) {
		t.Errorf("cloud-init's rule: %+v", r)
	}
	if r := s.Rules[2]; r.Who != "deploy" || r.All || !slices.Equal(r.Cmds, []string{"/usr/bin/systemctl restart app", "/usr/bin/systemctl reload app"}) || !slices.Equal(r.Runas, []string{"root"}) {
		t.Errorf("deploy's rule: %+v", r)
	}
	if r := s.Rules[3]; !r.Defaults || !r.All || r.OneUser() || r.Who != "backup" {
		t.Errorf("!authenticate: %+v", r)
	}
	for who, one := range map[string]bool{"admin": true, "%sudo": false, "ALL": false, "OPS": false, "a,b": false, "+netgrp": false, "#1000": false} {
		if (SudoRule{Who: who}).OneUser() != one {
			t.Errorf("OneUser(%q) != %v", who, one)
		}
	}
	some := newFake(true)
	some.files["/etc/sudoers"] = "deploy ALL=(root) NOPASSWD: SETENV: /usr/bin/systemctl restart app\nweb ALL=(ALL) PASSWD: ALL\n"
	if s := SudoNopasswd(some); len(s.Rules) != 1 || s.Rules[0].All {
		t.Errorf("some commands only: %+v", s)
	}
	every := newFake(true)
	every.files["/etc/sudoers"] = "ops ALL=(ALL) NOPASSWD: SETENV: ALL\n"
	if s := SudoNopasswd(every); len(s.Rules) != 1 || !s.Rules[0].All {
		t.Errorf("NOPASSWD: SETENV: ALL is every command: %+v", s)
	}

	locked := newFake(false)
	locked.files["/etc/sudoers"] = "#includedir /etc/sudoers.d\n"
	locked.files["/etc/sudoers.d/x"] = "a ALL=(ALL) NOPASSWD: ALL\n"
	locked.denied["/etc/sudoers.d"] = true
	locked.files["/etc/nsswitch.conf"] = "passwd: files\nsudoers: files sss\n"
	s = SudoNopasswd(locked)
	if len(s.Rules) != 0 || !slices.Contains(s.Unread, "/etc/sudoers.d (permission denied)") || !slices.Contains(s.Unread, "sudoers from sss (nsswitch.conf)") {
		t.Errorf("unread: %+v", s)
	}
	denied := newFake(false)
	denied.files["/etc/sudoers"] = "x"
	denied.denied["/etc/sudoers"] = true
	if s := SudoNopasswd(denied); len(s.Unread) != 1 || !strings.HasPrefix(s.Unread[0], "/etc/sudoers (permission denied)") {
		t.Errorf("sudoers itself unread: %+v", s)
	}
	if s := SudoNopasswd(newFake(true)); len(s.Rules)+len(s.Unread) != 0 {
		t.Errorf("no sudoers: %+v", s)
	}
}

// I-10: a reboot pending after an update: Debian's flag file, elsewhere a
// newer kernel in /boot than the one running.
func TestReboot(t *testing.T) {
	deb := newFake(true)
	deb.files["/run/reboot-required"] = "*** System restart required ***\n"
	deb.files["/run/reboot-required.pkgs"] = "linux-image-6.8.0-90-generic\nlibc6\nlibc6\n"
	if r := Reboot(deb, "debian", "6.8.0-88-generic"); !r.Pending || r.Why != "an update asks for a reboot (linux-image-6.8.0-90-generic, libc6)" {
		t.Errorf("debian: %+v", r)
	}
	if r := Reboot(newFake(true), "debian", "6.8.0-88-generic"); r.Pending || r.Unread != "" {
		t.Errorf("debian, none: %+v", r)
	}
	lockd := newFake(false)
	lockd.files["/run/reboot-required"] = ""
	lockd.denied["/run/reboot-required"] = true
	if r := Reboot(lockd, "debian", ""); r.Pending || r.Unread != "/run/reboot-required (permission denied)" {
		t.Errorf("debian, unread: %+v", r)
	}

	rhel := func(running string, kernels ...string) RebootPending {
		h := newFake(true)
		h.files["/boot/vmlinuz-0-rescue-0123456789abcdef"] = ""
		h.files["/boot/.vmlinuz-5.14.0-503.el9.x86_64.hmac"] = ""
		for _, k := range kernels {
			h.files["/boot/vmlinuz-"+k] = ""
		}
		return Reboot(h, "rhel", running)
	}
	if r := rhel("5.14.0-427.el9.x86_64", "5.14.0-427.el9.x86_64", "5.14.0-503.el9.x86_64", "5.14.0-70.el9.x86_64"); !r.Pending || r.Why != "kernel 5.14.0-503.el9.x86_64 is installed, 5.14.0-427.el9.x86_64 is running" {
		t.Errorf("rhel, newer kernel: %+v", r)
	}
	if r := rhel("5.14.0-503.el9.x86_64", "5.14.0-427.el9.x86_64", "5.14.0-503.el9.x86_64"); r.Pending {
		t.Errorf("rhel, newest running: %+v", r)
	}
	if r := rhel("5.14.0-1.container", "5.14.0-503.el9.x86_64"); r.Pending || r.Unread != "" {
		t.Errorf("running kernel not in /boot: %+v", r)
	}
	boot := newFake(false)
	boot.files["/boot/vmlinuz-1"] = ""
	boot.denied["/boot"] = true
	if r := Reboot(boot, "rhel", "1"); r.Unread != "/boot (permission denied)" {
		t.Errorf("/boot unread: %+v", r)
	}
}

// N-274-1: NOPASSWD holds for every command after it up to a PASSWD tag;
// a command alias is expanded, and one not told is every command.
func TestSudoNopasswdCommandList(t *testing.T) {
	for line, all := range map[string]bool{
		"bob ALL=(ALL) NOPASSWD: /bin/true, ALL":            true,
		"bob ALL=(ALL) NOPASSWD: /bin/ls, (root) ALL":       true,
		"Cmnd_Alias ANY = ALL\nbob ALL=(ALL) NOPASSWD: ANY": true,
		"bob ALL=(ALL) NOPASSWD: UNDEFINED":                 true,
		"bob ALL=(ALL) NOPASSWD: /bin/ls, PASSWD: ALL":      false,
		// MaskSecrets (every Source) masks what follows a NOPASSWD: tag when
		// it is an alias or an option: not told, so every command.
		"Cmnd_Alias SVC = /bin/systemctl restart a, /bin/systemctl restart b\nbob ALL=(ALL) NOPASSWD: SVC": true,
		"bob ALL=(ALL) NOPASSWD: CWD=/tmp /bin/ls":                                                         true,
		// After another tag the alias is not masked, and is expanded.
		"Cmnd_Alias SVC = /bin/systemctl restart a, /bin/systemctl restart b\nbob ALL=(ALL) NOPASSWD: SETENV: SVC": false,
		"Cmnd_Alias ANY = /bin/ls, ALL\nbob ALL=(ALL) NOPASSWD: SETENV: ANY":                                       true,
		"bob ALL=(ALL) NOPASSWD: SETENV: UNDEFINED":                                                                true,
		"bob ALL=(ALL) NOPASSWD: SETENV: /bin/ls":                                                                  false,
	} {
		h := newFake(true)
		h.files["/etc/sudoers"] = line + "\n"
		s := SudoNopasswd(h)
		if len(s.Rules) != 1 || s.Rules[0].All != all {
			t.Errorf("%q: want all=%v, got %+v", line, all, s.Rules)
		}
	}
	h := newFake(true)
	h.files["/etc/sudoers"] = "bob ALL=(ALL) PASSWD: ALL, /bin/ls\n"
	if s := SudoNopasswd(h); len(s.Rules) != 0 {
		t.Errorf("no NOPASSWD in force: %+v", s.Rules)
	}
	// S-274-1: spaces around a comma are a list, not one user.
	h.files["/etc/sudoers"] = "ubuntu , eve ALL=(ALL) NOPASSWD:ALL\n"
	if s := SudoNopasswd(h); len(s.Rules) != 1 || s.Rules[0].OneUser() || s.Rules[0].Who != "ubuntu,eve" {
		t.Errorf("a list with spaces: %+v", s.Rules)
	}
	// S-274-3: Defaults for some commands is those commands.
	h.files["/etc/sudoers"] = "Defaults!/bin/ls, /bin/cat !authenticate\nDefaults>deploy !authenticate\n"
	s := SudoNopasswd(h)
	if len(s.Rules) != 2 || s.Rules[0].All || !slices.Equal(s.Rules[0].Cmds, []string{"/bin/ls", "/bin/cat"}) || !s.Rules[1].All || !slices.Equal(s.Rules[1].Runas, []string{"deploy"}) {
		t.Errorf("Defaults for commands / a run-as: %+v", s.Rules)
	}
}

// N-274-2: cloud-init's default only for its default_user in its file, by
// its full path.
func TestSudoCloudDefault(t *testing.T) {
	cfg := "users:\n  - default\nsystem_info:\n  distro: ubuntu\n  default_user:\n    name: ubuntu\n    lock_passwd: True\n"
	for name, c := range map[string]struct {
		files map[string]string
		want  []bool // CloudDefault of each rule, in order
	}{
		"the real file, default user": {map[string]string{"/etc/sudoers.d/90-cloud-init-users": "ubuntu ALL=(ALL) NOPASSWD:ALL\n"}, []bool{true}},
		"the real file, eve added":    {map[string]string{"/etc/sudoers.d/90-cloud-init-users": "ubuntu ALL=(ALL) NOPASSWD:ALL\neve ALL=(ALL) NOPASSWD:ALL\n"}, []bool{true, false}},
		"99-custom with the header":   {map[string]string{"/etc/sudoers.d/99-custom": "# Created by cloud-init v. 24.1\nubuntu ALL=(ALL) NOPASSWD:ALL\n"}, []bool{false}},
		"copied to 91-deploy":         {map[string]string{"/etc/sudoers.d/91-deploy": "# Created by cloud-init v. 24.1\nubuntu ALL=(ALL) NOPASSWD:ALL\n"}, []bool{false}},
		"included from elsewhere":     {map[string]string{"/etc/sudoers": "#include /opt/x/90-cloud-init-users\n", "/opt/x/90-cloud-init-users": "ubuntu ALL=(ALL) NOPASSWD:ALL\n"}, []bool{false}},
		"sudoers with the header":     {map[string]string{"/etc/sudoers": "# Created by cloud-init v. 24.1\nubuntu ALL=(ALL) NOPASSWD:ALL\n"}, []bool{false}},
	} {
		h := newFake(true)
		h.files["/etc/sudoers"] = "@includedir /etc/sudoers.d\n"
		h.files["/etc/cloud/cloud.cfg"] = cfg
		for p, s := range c.files {
			h.files[p] = s
		}
		var got []bool
		for _, r := range SudoNopasswd(h).Rules {
			got = append(got, r.CloudDefault)
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
	// No cloud.cfg, or not the default user, or not read: never the default.
	h := newFake(true)
	h.files["/etc/sudoers"] = "@includedir /etc/sudoers.d\n"
	h.files["/etc/sudoers.d/90-cloud-init-users"] = "ubuntu ALL=(ALL) NOPASSWD:ALL\n"
	if s := SudoNopasswd(h); s.Rules[0].CloudDefault {
		t.Errorf("no cloud.cfg: %+v", s.Rules)
	}
	h.files["/etc/cloud/cloud.cfg"] = cfg
	h.files["/etc/cloud/cloud.cfg.d/90-mine.cfg"] = "system_info:\n  default_user:\n    name: \"admin\"\n"
	if CloudDefaultUser(h) != "admin" || SudoNopasswd(h).Rules[0].CloudDefault {
		t.Errorf("cloud.cfg.d sets another default user: %q", CloudDefaultUser(h))
	}
	h.denied["/etc/cloud/cloud.cfg.d/90-mine.cfg"] = true
	if CloudDefaultUser(h) != "" {
		t.Errorf("a cfg not read: %q", CloudDefaultUser(h))
	}
	if got := cfgDefaultUser("default_user:\n  name: ec2-user\n"); got != "ec2-user" {
		t.Errorf("top-level default_user: %q", got)
	}
	if got := cfgDefaultUser("other:\n  default_user:\n    name: eve\n"); got != "" {
		t.Errorf("default_user under another key: %q", got)
	}
	if got := cfgDefaultUser("users:\n  - name: bob\n"); got != "" {
		t.Errorf("a user that is not default_user: %q", got)
	}
}

// N-274-3: a kernel is compared with its own flavor only (+debug, UEK and
// RHCK apart).
func TestRebootKernelFlavor(t *testing.T) {
	boot := func(running string, kernels ...string) RebootPending {
		h := newFake(true)
		for _, k := range kernels {
			h.files["/boot/vmlinuz-"+k] = ""
		}
		return Reboot(h, "rhel", running)
	}
	for name, r := range map[string]RebootPending{
		"+debug of the same release": boot("5.14.0-503.el9.x86_64", "5.14.0-503.el9.x86_64", "5.14.0-503.el9.x86_64+debug"),
		"UEK newer, RHCK running":    boot("5.14.0-427.el9.x86_64", "5.14.0-427.el9.x86_64", "5.15.0-200.131.27.el9uek.x86_64"),
		"RHCK newer, UEK running":    boot("5.15.0-200.131.27.el9uek.x86_64", "5.15.0-200.131.27.el9uek.x86_64", "5.14.0-503.el9.x86_64"),
	} {
		if r.Pending {
			t.Errorf("%s: %+v", name, r)
		}
	}
	if r := boot("5.15.0-200.131.27.el9uek.x86_64", "5.15.0-200.131.27.el9uek.x86_64", "5.15.0-300.163.18.el9uek.x86_64", "5.14.0-503.el9.x86_64"); !r.Pending || !strings.Contains(r.Why, "5.15.0-300.163.18.el9uek") {
		t.Errorf("a newer UEK, UEK running: %+v", r)
	}
	if r := boot("5.14.0-427.el9.x86_64+debug", "5.14.0-427.el9.x86_64+debug", "5.14.0-503.el9.x86_64+debug"); !r.Pending {
		t.Errorf("a newer +debug, +debug running: %+v", r)
	}
}

// A user specification of several "host = commands" parts: each one's
// commands with their own tags; NOPASSWD on a line with no command told
// under it is every command, never dropped (fail closed).
func TestSudoRuleHostSpecs(t *testing.T) {
	for line, want := range map[string]struct{ ok, all bool }{
		"bob h1 = /bin/ls : h2 = NOPASSWD: ALL":                  {true, true},
		"bob h1 = NOPASSWD: /bin/ls : h2 = NOPASSWD: ALL":        {true, true},
		"bob h1 = NOPASSWD: /bin/ls : h2 = ALL":                  {true, true}, // over-warns: ALL after a NOPASSWD anywhere (fail closed)
		"bob h1 = (root) NOPASSWD: /bin/ls : h2 = (ALL:ALL) ALL": {true, true}, // over-warns: ALL after a NOPASSWD anywhere (fail closed)
		"bob ALL = (ALL:ALL) NOPASSWD: CWD=/tmp /bin/ls":         {true, false},
		"bob ALL=(ALL) NOPASSWD: /usr/bin/env A=1":               {true, false},
		"bob ALL=(ALL) NOPASSWD:":                                {true, true},
		"bob ALL=(ALL) NOPASSWD":                                 {false, false}, // not a tag: sudoers refuses the file
		"bob ALL=(ALL) ALL # NOPASSWD in a comment cut":          {false, false},
	} {
		r, ok := sudoRule(sudoRaw{file: "/etc/sudoers", line: line}, nil)
		if ok != want.ok || ok && r.All != want.all {
			t.Errorf("%q: ok %v all %v, want %+v (%+v)", line, ok, r.All, want, r)
		}
	}
	// A digest's colon is not a separator; and were one taken for it, the
	// line read whole as well keeps ALL in (fail closed).
	d := "sha256:" + strings.Repeat("A", 43) + "="
	r, ok := sudoRule(sudoRaw{file: "/etc/sudoers", line: "bob ALL = NOPASSWD: " + d + " /bin/true, ALL"}, nil)
	if !ok || !r.All {
		t.Errorf("a digest before /bin/true, ALL: %+v", r)
	}
	r, ok = sudoRule(sudoRaw{file: "/etc/sudoers", line: "bob ALL = NOPASSWD: " + d + " /bin/true"}, nil)
	if !ok || r.All || !slices.Equal(r.Cmds, []string{d + " /bin/true"}) {
		t.Errorf("a digest before /bin/true: %+v", r)
	}
	// A word named like a digest or a tag before a real separator: the
	// split at every ':' (and ALL after NOPASSWD anywhere) keeps it in.
	if r, ok := sudoRule(sudoRaw{file: "/etc/sudoers", line: "bob h1 = NOPASSWD: /bin/ls sha256 : h2 = NOPASSWD: ALL"}, nil); !ok || !r.All {
		t.Errorf("sha256 before a separator, then ALL: %+v", r)
	}
	if r, ok := sudoRule(sudoRaw{file: "/etc/sudoers", line: "bob h1 = NOPASSWD: /bin/ls sha256 : h2 = NOPASSWD: ANY"}, map[string][]string{"ANY": {"ALL"}}); !ok || !r.All {
		t.Errorf("sha256 before a separator, then an alias of ALL: %+v", r)
	}
	if !nopassAllToken(" ALL = NOPASSWD:ALL") || nopassAllToken(" ALL = (ALL:ALL) NOPASSWD: /bin/ls, PASSWD: ALL") || nopassAllToken(" ALL = (ALL) ALL") || nopassAllToken(" ALL = (root) NOPASSWD: /bin/ls, ( ALL ) /bin/cat") {
		t.Error("nopassAllToken")
	}
	// An argument with a ':' and an '=' looks like another host part: the
	// whole-line reading keeps the ALL after it.
	if r, ok := sudoRule(sudoRaw{file: "/etc/sudoers", line: "bob ALL = NOPASSWD: /usr/bin/printf a:b=c, ALL"}, nil); !ok || !r.All {
		t.Errorf("an argument like a host part: %+v", r)
	}
	h := newFake(true)
	h.files["/etc/sudoers"] = "bob h1 = /bin/ls : h2 = NOPASSWD: ALL\n"
	if s := SudoNopasswd(h); len(s.Rules) != 1 || !s.Rules[0].All {
		t.Errorf("another host's NOPASSWD: ALL, read: %+v", s.Rules)
	}
}
