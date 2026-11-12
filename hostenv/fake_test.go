package hostenv

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"
)

// fakeHost is an in-memory Source for tests. Paths not present do not exist;
// paths in denied fail with a permission error.
type fakeHost struct {
	info   SourceInfo
	files  map[string]string
	links  map[string]string
	cmds   map[string]CmdResult
	denied map[string]bool
}

func newFake(elevated bool) *fakeHost {
	return &fakeHost{
		info:  SourceInfo{GOOS: "linux", GOARCH: "arm64", Elevated: elevated, RecordedAt: time.Date(2026, 11, 12, 3, 0, 0, 0, time.UTC)},
		files: map[string]string{}, links: map[string]string{}, cmds: map[string]CmdResult{}, denied: map[string]bool{},
	}
}

func (h *fakeHost) Info() SourceInfo { return h.info }

func (h *fakeHost) err(op, p string) error {
	if h.denied[p] {
		return &fs.PathError{Op: op, Path: p, Err: fs.ErrPermission}
	}
	return &fs.PathError{Op: op, Path: p, Err: fs.ErrNotExist}
}

func (h *fakeHost) ReadFile(p string) ([]byte, error) {
	if s, ok := h.files[p]; ok && !h.denied[p] {
		return []byte(MaskSecrets(s)), nil
	}
	return nil, h.err("open", p)
}

// ReadFileNoFollow refuses paths present in links, as O_NOFOLLOW would.
func (h *fakeHost) ReadFileNoFollow(p string) ([]byte, error) {
	if _, ok := h.links[p]; ok {
		return nil, fmt.Errorf("%w: %s", ErrSymlink, p)
	}
	return h.ReadFile(p)
}

func (h *fakeHost) ReadDir(p string) ([]string, error) {
	if h.denied[p] {
		return nil, h.err("open", p)
	}
	seen := map[string]bool{}
	prefix := strings.TrimSuffix(p, "/") + "/"
	for _, m := range []map[string]string{h.files, h.links} {
		for k := range m {
			if rest, ok := strings.CutPrefix(k, prefix); ok {
				name, _, _ := strings.Cut(rest, "/")
				seen[name] = true
			}
		}
	}
	if len(seen) == 0 {
		return nil, h.err("open", p)
	}
	var out []string
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

func (h *fakeHost) Readlink(p string) (string, error) {
	if t, ok := h.links[p]; ok && !h.denied[p] {
		return t, nil
	}
	return "", h.err("readlink", p)
}

func (h *fakeHost) Run(_ context.Context, argv []string) (CmdResult, error) {
	if r, ok := h.cmds[argvKey(argv)]; ok {
		return r, nil
	}
	return CmdResult{}, &fs.PathError{Op: "exec", Path: argv[0], Err: fs.ErrNotExist}
}

// debianHost is a small Debian 12 machine with one of everything the checks
// look for: a root password login, an ld.so.preload, a process running from
// /tmp and one whose binary was deleted.
func debianHost(elevated bool) *fakeHost {
	h := newFake(elevated)
	h.files["/etc/os-release"] = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nVERSION=\"12 (bookworm)\"\nID=debian\n"
	h.files["/proc/sys/kernel/osrelease"] = "6.1.0-26-arm64\n"
	h.files["/proc/1/cgroup"] = "0::/init.scope\n"
	h.files["/etc/passwd"] = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nalice:x:1000:1000:Alice Example,,,:/home/alice:/bin/bash\n"
	h.files["/etc/group"] = "root:x:0:\nsudo:x:27:alice\nwww-data:x:33:\n"
	h.cmds[argvKey(dpkgArgv)] = CmdResult{Stdout: []byte("bash\t\t5.2.15-2+b7\tarm64\tii \nlibssl3\topenssl\t3.0.14-1~deb12u2\tarm64\tii \nold\t\t1.0\tarm64\trc \n")}
	h.files["/etc/ssh/sshd_config"] = "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nMatch User bob\n  PasswordAuthentication no\n"
	h.files["/etc/ssh/sshd_config.d/50-cloud.conf"] = "PasswordAuthentication yes\n"
	h.files["/etc/crontab"] = "SHELL=/bin/sh\n# m h dom mon dow user command\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n"
	h.files["/etc/ld.so.preload"] = "/usr/lib/libprocesshider.so\n"
	h.files["/etc/systemd/system/backdoor.service"] = "[Service]\nExecStart=/tmp/.x/agent --token=" + fakeSecret() + "\n"
	h.files["/home/alice/.ssh/authorized_keys"] = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyMaterialForTestsOnly0000000000000 alice@laptop.example.com\n"
	// processes: 1 systemd, 4242 from /tmp, 4243 deleted binary, 7 kernel thread
	h.files["/proc/1/status"] = "Name:\tsystemd\nPPid:\t0\nUid:\t0\t0\t0\t0\n"
	h.files["/proc/1/cmdline"] = "/sbin/init\x00"
	h.links["/proc/1/exe"] = "/usr/lib/systemd/systemd"
	h.files["/proc/4242/status"] = "Name:\tkworkerds\nPPid:\t1\nUid:\t33\t33\t33\t33\n"
	h.files["/proc/4242/cmdline"] = "/tmp/.x/kworkerds\x00--password=" + fakeSecret() + "\x00"
	h.links["/proc/4242/exe"] = "/tmp/.x/kworkerds"
	h.links["/proc/4242/fd/3"] = "socket:[9001]"
	h.files["/proc/4243/status"] = "Name:\tsshd\nPPid:\t1\nUid:\t0\t0\t0\t0\n"
	h.links["/proc/4243/exe"] = "/usr/sbin/sshd (deleted)"
	h.links["/proc/4243/fd/3"] = "socket:[9002]"
	h.files["/proc/7/status"] = "Name:\tkthreadd\nPPid:\t2\nUid:\t0\t0\t0\t0\n"
	h.files["/proc/net/tcp"] = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9002 1 0 100 0 0 10 0\n" +
		"   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000    33        0 9001 1 0 100 0 0 10 0\n" +
		"   2: 0F02000A:0016 6401A8C0:D431 01 00000000:00000000 02:000A7F2B 00000000     0        0 9003 4 0 20 4 29 10 -1\n"
	h.files["/proc/net/udp"] = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n" +
		"  1: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 9100 2 0 0\n"
	return h
}

// fakeSecret is assembled at run time so no secret-shaped literal sits in
// the source for scanners to trip on.
func fakeSecret() string { return strings.Repeat("q7", 4) + "zx" + "91" }
