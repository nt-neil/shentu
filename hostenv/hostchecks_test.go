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
	// Who each is for, and which file cloud-init wrote.
	if r := s.Rules[0]; r.Who != "admin" || !r.All || !r.CloudInit || !r.OneUser() {
		t.Errorf("cloud-init's rule: %+v", r)
	}
	if r := s.Rules[2]; r.Who != "deploy" || r.All || r.CloudInit {
		t.Errorf("deploy's rule: %+v", r)
	}
	if r := s.Rules[3]; !r.Defaults || !r.All || r.OneUser() {
		t.Errorf("!authenticate: %+v", r)
	}
	for who, one := range map[string]bool{"admin": true, "%sudo": false, "ALL": false, "OPS": false, "a,b": false, "+netgrp": false} {
		if (SudoRule{Who: who}).OneUser() != one {
			t.Errorf("OneUser(%q) != %v", who, one)
		}
	}
	hdr := newFake(true)
	hdr.files["/etc/sudoers"] = "#includedir /etc/sudoers.d\n"
	hdr.files["/etc/sudoers.d/cloud"] = "\n# Created by cloud-init v. 24.1 on Thu, 01 Jan 2026 00:00:00 +0000\n\n# User rules for ubuntu\nubuntu ALL=(ALL) NOPASSWD:ALL\n"
	if s := SudoNopasswd(hdr); len(s.Rules) != 1 || !s.Rules[0].CloudInit {
		t.Errorf("cloud-init's header: %+v", s)
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
