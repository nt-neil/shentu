package hostenv

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestParsers(t *testing.T) {
	osr := ParseOSRelease([]byte("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\nVERSION=\"24.04.1 LTS (Noble Numbat)\"\n# c\n"))
	if osr["VERSION_ID"] != "24.04" || OSVEcosystem(osr) != "Ubuntu:24.04:LTS" || LinuxFamily(osr["ID"], osr["ID_LIKE"]) != "debian" {
		t.Errorf("os-release: %v eco=%q", osr, OSVEcosystem(osr))
	}
	if got := LinuxFamily("rocky", "rhel centos fedora"); got != "rhel" {
		t.Errorf("rocky family %q", got)
	}
	if got := OSVEcosystem(map[string]string{"ID": "alpine", "VERSION_ID": "3.20.3"}); got != "Alpine:v3.20" {
		t.Errorf("alpine eco %q", got)
	}

	ip, port := parseHexAddr("0100007F:0016")
	if ip.String() != "127.0.0.1" || port != 22 {
		t.Errorf("hex addr %v %d", ip, port)
	}
	ip6, _ := parseHexAddr("00000000000000000000000001000000:0050")
	if ip6.String() != "::1" {
		t.Errorf("hex v6 %v", ip6)
	}
	if ip, _ := parseHexAddr("zz:0016"); ip != nil {
		t.Error("bad hex accepted")
	}

	pk := ParseDpkgQuery([]byte("bash\t\t5.2\tarm64\tii \nlibssl3\topenssl\t3.0\tarm64\tii \ngone\t\t1\tarm64\trc \n"))
	if len(pk) != 2 || pk[1].Source != "openssl" || pk[0].Source != "" {
		t.Errorf("dpkg %+v", pk)
	}
	rp := ParseRpmQA([]byte("openssl\t1:3.0.7-27.el9\taarch64\ngpg-pubkey\t0:abc-def\t(none)\n"))
	if len(rp) != 1 || rp[0].Version != "1:3.0.7-27.el9" {
		t.Errorf("rpm %+v", rp)
	}
	ap := ParseApkInstalled([]byte("C:Q1x\nP:musl\nV:1.2.5-r0\nA:aarch64\no:musl\n\nP:libcrypto3\nV:3.3.2-r0\no:openssl\n"))
	if len(ap) != 2 || ap[1].Source != "openssl" || ap[0].Source != "" {
		t.Errorf("apk %+v", ap)
	}

	for _, l := range []string{"PermitRootLogin=yes", "PermitRootLogin = yes", "  permitrootlogin\t\"yes\"", "PermitRootLogin yes # c"} {
		d, _ := ParseSSHDConfig([]byte(l))
		if len(d) != 1 || d[0] != (SSHDDirective{"permitrootlogin", "yes"}) {
			t.Errorf("sshd %q -> %+v", l, d)
		}
	}
	dirs, match := ParseSSHDConfig([]byte("# c\nInclude a/*.conf b.conf\nPermitRootLogin YES\nMatch User x\nPasswordAuthentication no\n"))
	if !match || len(dirs) != 3 || dirs[2] != (SSHDDirective{"permitrootlogin", "yes"}) {
		t.Errorf("sshd %+v %v", dirs, match)
	}
	if c := ParseCron([]byte("SHELL=/bin/sh\nPATH=/usr/bin\n*/5 * * * * root FOO=1 /x\n# no\n")); len(c) != 1 {
		t.Errorf("cron %q", c)
	}
	if st := ParseProcStatus([]byte("Name:\tnginx\nPPid:\t1\nUid:\t33\t33\t33\t33\n")); st != (ProcStatus{"nginx", 1, "33"}) {
		t.Errorf("status %+v", st)
	}
	if c := ParseCmdline([]byte("app\x00--password=" + fakeSecret() + "\x00")); strings.Contains(c, fakeSecret()) {
		t.Errorf("cmdline not masked: %q", c)
	}
	if CanLoginShell("/usr/sbin/nologin") || CanLoginShell("") || !CanLoginShell("/bin/bash") {
		t.Error("login shell")
	}
	ak := ParseAuthorizedKeys([]byte(`command="/bin/x" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA== c` + "\nssh-rsa notbase64!! d\n"))
	if len(ak) != 2 || !ak[0].Options || ak[1].Options || !strings.HasPrefix(ak[0].Fingerprint, "SHA256:") {
		t.Errorf("authorized_keys %+v", ak)
	}
}

func TestLinuxCollectorRoot(t *testing.T) {
	f := Collect(context.Background(), debianHost(true))
	if f.Schema != SchemaVersion || f.Collector.Name != "linux" {
		t.Fatalf("header %+v", f.Collector)
	}
	if f.Platform.Status != StatusOK || f.Platform.Value.Distro != "debian" || f.Platform.Value.Kernel != "6.1.0-26-arm64" || f.Platform.Value.InContainer {
		t.Errorf("platform %+v", f.Platform)
	}
	if f.Packages.Status != StatusOK || f.Packages.Value.Ecosystem != "Debian:12" || len(f.Packages.Value.Items) != 2 {
		t.Errorf("packages %+v", f.Packages)
	}
	var admins []string
	for _, a := range f.Accounts.Value {
		if a.IsAdmin {
			admins = append(admins, a.Name)
		}
	}
	if !reflect.DeepEqual(admins, []string{"root", "alice"}) {
		t.Errorf("admins %v", admins)
	}
	byPID := map[int]Process{}
	for _, p := range f.Processes.Value {
		byPID[p.PID] = p
	}
	if f.Processes.Status != StatusOK || !byPID[4242].InTemp || byPID[4243].ExeExists || byPID[4243].Exe != "/usr/sbin/sshd" || byPID[7].ExeKnown || byPID[4242].User != "www-data" {
		t.Errorf("processes %+v", f.Processes)
	}
	if strings.Contains(byPID[4242].Cmdline, fakeSecret()) {
		t.Errorf("cmdline leaked a password: %q", byPID[4242].Cmdline)
	}
	want := []Listener{{"tcp", "0.0.0.0", 22, 4243, ""}, {"tcp", "127.0.0.1", 8080, 4242, ""}, {"udp", "0.0.0.0", 68, 0, ""}}
	if f.Listeners.Status != StatusOK || !reflect.DeepEqual(f.Listeners.Value, want) {
		t.Errorf("listeners %+v", f.Listeners)
	}
	ssh := f.RemoteAccess.SSH
	if ssh.Status != StatusOK || ssh.Value.Settings["permitrootlogin"] != "yes" || ssh.Value.Settings["passwordauthentication"] != "yes" {
		t.Errorf("ssh %+v", ssh)
	}
	kinds := map[string]int{}
	for _, it := range f.Persistence.Value {
		kinds[it.Kind]++
		if strings.Contains(it.Command+it.Detail, fakeSecret()) || strings.Contains(it.Detail, "AAAA") {
			t.Errorf("persistence leaked: %+v", it)
		}
	}
	if !reflect.DeepEqual(kinds, map[string]int{"cron": 1, "ld_preload": 1, "systemd": 1, "authorized_key": 1}) {
		t.Errorf("persistence kinds %v", kinds)
	}
	if f.RemoteAccess.RDP.Status != StatusNotApplicable || f.Firewall.Status != StatusUnknown || f.Firewall.Reason != ReasonNotCollected {
		t.Errorf("rdp/firewall %+v %+v", f.RemoteAccess.RDP, f.Firewall)
	}
}

// Without root, hidden data must surface as partial/unknown, never as clean.
func TestLinuxCollectorPermissionDenied(t *testing.T) {
	h := debianHost(false)
	h.denied["/proc/4243/exe"] = true
	h.denied["/proc/4243/fd"] = true
	h.denied["/etc/ssh/sshd_config.d"] = true
	h.denied["/var/spool/cron/crontabs"] = true
	h.files["/var/spool/cron/crontabs/alice"] = "* * * * * /x\n"
	f := Collect(context.Background(), h)
	if f.Processes.Status != StatusPartial || f.Processes.Reason != ReasonPermission {
		t.Errorf("processes %s/%s", f.Processes.Status, f.Processes.Reason)
	}
	if f.Listeners.Status != StatusPartial {
		t.Errorf("listeners %s", f.Listeners.Status)
	}
	ssh := f.RemoteAccess.SSH
	if ssh.Status != StatusPartial || ssh.Value.Settings["passwordauthentication"] != "unknown" || ssh.Value.Settings["permitrootlogin"] != "unknown" {
		t.Errorf("ssh %+v", ssh)
	}
	if f.Persistence.Status != StatusPartial || !strings.Contains(f.Persistence.Detail, "/var/spool/cron/crontabs") {
		t.Errorf("persistence %s %q", f.Persistence.Status, f.Persistence.Detail)
	}

	h = debianHost(false)
	h.denied["/etc/passwd"] = true
	f = Collect(context.Background(), h)
	if f.Accounts.Status != StatusUnknown || f.Accounts.Reason != ReasonPermission {
		t.Errorf("accounts %+v", f.Accounts)
	}
}

func TestPackagesCommandMissing(t *testing.T) {
	h := debianHost(true)
	h.cmds = map[string]CmdResult{}
	f := Collect(context.Background(), h)
	if f.Packages.Status != StatusUnknown || f.Packages.Reason != ReasonNotInstalled {
		t.Errorf("packages %+v", f.Packages)
	}
}

func TestUnsupportedPlatform(t *testing.T) {
	h := newFake(true)
	h.info.GOOS = "windows"
	f := Collect(context.Background(), h)
	if f.Processes.Status != StatusUnknown || f.Processes.Reason != ReasonUnsupported || f.Platform.Value.OS != "windows" {
		t.Errorf("unsupported %+v", f.Processes)
	}
}

func TestRecordReplayMasked(t *testing.T) {
	h := debianHost(true)
	h.files["/etc/hosts"] = "127.0.0.1 localhost\n192.168.1.100 web01.corp.example web01\n203.0.113.9 api\n"
	rec := NewRecorder(h)
	live := Collect(context.Background(), rec)
	dir := filepath.Join(t.TempDir(), "fx")
	m := &Masker{Hosts: []string{"web01.corp.example", "web01"}, Users: []string{"alice"}}
	if err := rec.Save(dir, m); err != nil {
		t.Fatal(err)
	}
	all := readTree(t, dir)
	for _, leak := range []string{"alice", "Alice", "web01", "192.168.1.100", "203.0.113.9", "0F02000A", "6401A8C0",
		"FakeKeyMaterial", "laptop.example.com", fakeSecret()} {
		if strings.Contains(all, leak) {
			t.Errorf("fixture still contains %q", leak)
		}
	}
	if !strings.Contains(all, "/home/user1/.ssh/authorized_keys") || !strings.Contains(all, "0100007F:1F90") {
		t.Error("masking changed paths inconsistently or touched loopback")
	}
	if err := rec.Save(dir, m); err == nil {
		t.Error("Save wrote into an existing directory")
	}
	if st, _ := os.Stat(filepath.Join(dir, "manifest.json")); st == nil || st.Mode().Perm() != 0o600 {
		t.Errorf("manifest mode %v, want 0600", st)
	}

	rp, err := LoadReplay(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := Collect(context.Background(), rp)
	if got.Persistence.Status != StatusOK || len(got.Persistence.Value) != len(live.Persistence.Value) {
		t.Errorf("replayed persistence %+v", got.Persistence)
	}
	if len(got.Listeners.Value) != len(live.Listeners.Value) || got.Packages.Status != StatusOK {
		t.Errorf("replay differs: %+v", got.Listeners)
	}
	for _, a := range got.Accounts.Value {
		if a.Name == "alice" {
			t.Error("replayed account not masked")
		}
	}
	// A replay twice gives the same facts.
	again := Collect(context.Background(), rp)
	if !reflect.DeepEqual(mustJSON(t, got), mustJSON(t, again)) {
		t.Error("replay not deterministic")
	}
}

func TestReplayNotRecorded(t *testing.T) {
	rp := &Replay{info: SourceInfo{GOOS: "linux"}, byK: map[string]*entry{}}
	_, err := rp.ReadFile("/etc/os-release")
	if !errors.Is(err, ErrNotRecorded) || Classify(err) != ReasonNotRecorded {
		t.Fatalf("err %v", err)
	}
	f := Collect(context.Background(), rp)
	if f.Accounts.Reason != ReasonNotRecorded {
		t.Errorf("accounts %+v", f.Accounts)
	}
}

func TestMaskerIPClasses(t *testing.T) {
	m := &Masker{}
	m.init()
	got := m.text("a 10.1.2.3 b 8.8.8.8 c 127.0.0.1 d 0.0.0.0 e 10.1.2.3 f fe80::1ff:fe23:4567:890a g 2400:cb00::1 h ::1 i 1.2.3", true, true)
	want := "a 10.0.0.1 b 198.51.100.1 c 127.0.0.1 d 0.0.0.0 e 10.0.0.1 f fe80::1 g 2001:db8::2 h ::1 i 1.2.3"
	if got != want {
		t.Errorf("\n got %s\nwant %s", got, want)
	}
	if s := m.procNet("0F02000A:0016 0100007F:0050"); s != encodeHexAddr(m.ip(mustIP("10.0.2.15")))+":0016 0100007F:0050" {
		t.Errorf("procnet %s", s)
	}
}

// The secret rules here must stay identical to the root package's mask.go.
func TestMaskSecretsMatchesRoot(t *testing.T) {
	b, err := os.ReadFile("../mask.go")
	if err != nil {
		t.Skip("root mask.go not found")
	}
	lits := regexp.MustCompile("regexp.MustCompile\\(`([^`]*)`\\)").FindAllStringSubmatch(string(b), -1)
	if len(lits) != len(secretRules) {
		t.Fatalf("root has %d rules, hostenv has %d", len(lits), len(secretRules))
	}
	for i, l := range lits {
		if l[1] != secretRules[i].re.String() {
			t.Errorf("rule %d differs:\nroot    %s\nhostenv %s", i, l[1], secretRules[i].re.String())
		}
	}
}

func readTree(t *testing.T, dir string) string {
	var sb strings.Builder
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			sb.Write(b)
		}
		return nil
	})
	return sb.String()
}

func mustJSON(t *testing.T, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Failures other than "missing" and anything over the cap must surface.
func TestPersistenceFailClosed(t *testing.T) {
	h := debianHost(true)
	h.links["/home/alice/.ssh/authorized_keys2"] = "/etc/shadow" // planted link
	var cron strings.Builder
	for i := 0; i < MaxPersistenceItems+5; i++ {
		cron.WriteString("* * * * * root /bin/true\n")
	}
	h.files["/etc/cron.d/flood"] = cron.String()
	f := Collect(context.Background(), h)
	if f.Persistence.Status != StatusPartial || f.Persistence.Reason != ReasonTruncated {
		t.Errorf("cap: %s %s %q", f.Persistence.Status, f.Persistence.Reason, f.Persistence.Detail)
	}
	if !strings.Contains(f.Persistence.Detail, "authorized_keys2 (symlink_not_followed)") {
		t.Errorf("symlink not reported: %q", f.Persistence.Detail)
	}
	n := map[string]int{}
	for _, it := range f.Persistence.Value {
		n[it.Kind]++
	}
	if n["cron"] != MaxPersistenceItems || n["ld_preload"] != 1 || n["authorized_key"] != 1 {
		t.Errorf("per-kind cap starved other kinds: %v", n)
	}

	h = debianHost(true)
	h.denied["/proc/4243/exe"] = true
	if f := Collect(context.Background(), h); f.Processes.Status != StatusPartial {
		t.Errorf("hidden process as root: %s", f.Processes.Status)
	}
}
