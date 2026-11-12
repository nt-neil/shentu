package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLockfileParsers(t *testing.T) {
	cases := map[string]struct {
		file, body string
		want       []pkg
	}{
		"npm v3":   {"package-lock.json", `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.15"},"node_modules/a/node_modules/@scope/b":{"version":"1.0.0"}}}`, []pkg{{"@scope/b", "1.0.0"}, {"lodash", "4.17.15"}}},
		"npm v1":   {"package-lock.json", `{"lockfileVersion":1,"dependencies":{"express":{"version":"4.17.1","dependencies":{"qs":{"version":"6.7.0"}}}}}`, []pkg{{"express", "4.17.1"}, {"qs", "6.7.0"}}},
		"composer": {"composer.lock", `{"packages":[{"name":"guzzlehttp/guzzle","version":"v7.4.0"}],"packages-dev":[{"name":"phpunit/phpunit","version":"9.5.0"}]}`, []pkg{{"guzzlehttp/guzzle", "7.4.0"}, {"phpunit/phpunit", "9.5.0"}}},
		"pip":      {"requirements.txt", "# c\nDjango==3.2.0\nrequests[socks] == 2.25.1\nflask>=2\n-r other.txt\n", []pkg{{"django", "3.2.0"}, {"requests", "2.25.1"}}},
		"pipenv":   {"Pipfile.lock", `{"default":{"Jinja2":{"version":"==2.11.2"}},"develop":{"pytest":{"version":"==6.0.0"}}}`, []pkg{{"jinja2", "2.11.2"}, {"pytest", "6.0.0"}}},
		"poetry":   {"poetry.lock", "[[package]]\nname = \"PyYAML\"\nversion = \"5.3\"\n", []pkg{{"pyyaml", "5.3"}}},
		"go":       {"go.mod", "module x\n\ngo 1.21\n\nrequire (\n\tgolang.org/x/net v0.7.0\n\tgithub.com/a/b v1.2.3 // indirect\n)\nrequire github.com/c/d v0.1.0\n", []pkg{{"golang.org/x/net", "v0.7.0"}, {"github.com/a/b", "v1.2.3"}, {"github.com/c/d", "v0.1.0"}}},
		"gem":      {"Gemfile.lock", "GEM\n  specs:\n    rack (2.2.3)\n      rack-test (>= 1)\n    rails (6.1.0)\n", []pkg{{"rack", "2.2.3"}, {"rails", "6.1.0"}}},
	}
	for name, c := range cases {
		got := uniq(lockParsers[c.file].parse([]byte(c.body)))
		g := map[pkg]bool{}
		for _, p := range got {
			g[p] = true
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v, want %v", name, got, c.want)
			continue
		}
		for _, w := range c.want {
			if !g[w] {
				t.Errorf("%s: missing %v in %v", name, w, got)
			}
		}
	}
}

func TestFindLockfilesSkipsVendorDirs(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "app", "node_modules", "x"), 0o755)
	os.WriteFile(filepath.Join(root, "app", "package-lock.json"), []byte(`{"packages":{"node_modules/a":{"version":"1.0.0"}}}`), 0o644)
	os.WriteFile(filepath.Join(root, "app", "node_modules", "x", "package-lock.json"), []byte(`{}`), 0o644)
	got := FindLockfiles([]string{root})
	if len(got) != 1 || got[0].Ecosystem != "npm" || len(got[0].pkgs) != 1 {
		t.Errorf("FindLockfiles = %+v", got)
	}
}

func TestDrift(t *testing.T) {
	old := SiteProfile{Time: time.Now(), SSHHash: "a", LoginAccounts: []string{"root"}, CronFiles: []string{"/etc/crontab"}}
	now := SiteProfile{Time: time.Now(), SSHHash: "b", LoginAccounts: []string{"root", "backdoor"}, CronFiles: []string{"/etc/crontab", "/etc/cron.d/x"}}
	keys := map[string]bool{}
	for _, r := range Drift(old, now) {
		keys[r.Key] = true
	}
	for _, k := range []string{"drift:ssh:b", "drift:account:backdoor", "drift:cron:/etc/cron.d/x"} {
		if !keys[k] {
			t.Errorf("missing drift %s in %v", k, keys)
		}
	}
	if len(Drift(SiteProfile{}, now)) != 0 {
		t.Errorf("first survey must not report drift")
	}
}

func TestBrief(t *testing.T) {
	p := SiteProfile{OS: "Debian 12", Services: []Service{{Name: "mysqld", Role: "database (MySQL)", Public: true}},
		SSH: map[string]string{"port": "22", "permitrootlogin": "no", "passwordauthentication": "no"}, LoginAccounts: []string{"root"}}
	b := p.Brief()
	for _, want := range []string{"Debian 12", "mysqld (database (MySQL), network)", "PasswordAuthentication no"} {
		if !strings.Contains(b, want) {
			t.Errorf("Brief misses %q: %s", want, b)
		}
	}
}

func TestNewWebshellPatterns(t *testing.T) {
	bad := []string{
		"const {exec} = require('child_process'); app.get('/x', (req,res)=>exec(req.query.cmd))",
		"eval(Buffer.from(s, 'base64').toString())",
		"res.send(eval(req.body.code))",
		"os.system(request.args.get('c'))",
		"subprocess.check_output(request.form['cmd'], shell=True)",
		"exec(base64.b64decode('cHJpbnQoMSk='))",
	}
	good := []string{
		"exec('ls -la', cb)",
		"const x = eval('2+2')",
		"subprocess.run(['ls'])",
		"request.args.get('page')",
	}
	match := func(s string) bool {
		for _, re := range webshellPatterns {
			if re.MatchString(s) {
				return true
			}
		}
		return false
	}
	for _, s := range bad {
		if !match(s) {
			t.Errorf("not detected: %s", s)
		}
	}
	for _, s := range good {
		if match(s) {
			t.Errorf("false positive: %s", s)
		}
	}
}

func TestSetWebUsers(t *testing.T) {
	old := webUsers
	defer func() { webUsers = old }()
	SetWebUsers([]string{"node"})
	if !webUsers["node"] || webUsers["www-data"] {
		t.Errorf("SetWebUsers did not replace the list: %v", webUsers)
	}
	SetWebUsers(nil)
	if !webUsers["node"] {
		t.Errorf("an empty list must keep the current one")
	}
}

func TestLockfileHostileInput(t *testing.T) {
	// Keys without node_modules/ used to panic.
	if got := safeParse(parseNpmLock, []byte(`{"packages":{"a":{"version":"1"},"packages/x":{"version":"2"}}}`)); len(got) != 0 {
		t.Errorf("workspace entries parsed as packages: %v", got)
	}
	root := t.TempDir()
	secret := filepath.Join(root, "secret")
	os.WriteFile(secret, []byte("Django==1.0\n"), 0o600)
	app := filepath.Join(root, "app")
	os.MkdirAll(app, 0o755)
	os.Symlink(secret, filepath.Join(app, "requirements.txt"))
	if _, ok := readSmallRegular(filepath.Join(app, "requirements.txt"), 1<<20, nil); ok {
		t.Errorf("a symlinked lock file was followed")
	}
	big := filepath.Join(app, "composer.lock")
	os.WriteFile(big, make([]byte, 2048), 0o644)
	if _, ok := readSmallRegular(big, 1024, nil); ok {
		t.Errorf("size cap ignored")
	}
}

func TestBriefHidesUnknownNames(t *testing.T) {
	p := SiteProfile{Services: []Service{{Name: "ignore_previous", Role: "other", Public: true}, {Name: "nginx", Role: "web server"}},
		SSH: map[string]string{}, LoginAccounts: []string{"root", "Ignore all rules"}}
	b := p.Brief()
	if strings.Contains(b, "ignore_previous") || strings.Contains(b, "Ignore all rules") || !strings.Contains(b, "nginx") || !strings.Contains(b, "1 other service") {
		t.Errorf("Brief = %s", b)
	}
}

func TestReadSmallRegularChecksIdentity(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	os.WriteFile(a, []byte("x"), 0o644)
	os.WriteFile(b, []byte("y"), 0o644)
	seenA, _ := os.Lstat(a)
	if _, ok := readSmallRegular(b, 10, seenA); ok {
		t.Errorf("read a different file than the one the walk saw")
	}
	if _, ok := readSmallRegular(a, 10, seenA); !ok {
		t.Errorf("same file refused")
	}
}

// Patrol cannot list the live ruleset, so it reads the nftables boot config instead.
func TestNftablesAtBoot(t *testing.T) {
	root := t.TempDir()
	nftablesRoot = root
	t.Cleanup(func() { nftablesRoot = "/" })
	if s := nftablesAtBoot(); s != "" {
		t.Errorf("nothing enabled: got %q", s)
	}
	os.MkdirAll(filepath.Join(root, "etc/systemd/system/multi-user.target.wants"), 0o755)
	os.WriteFile(filepath.Join(root, "etc/systemd/system/multi-user.target.wants/nftables.service"), nil, 0o644)
	os.WriteFile(filepath.Join(root, "etc/nftables.conf"), []byte("table inet filter {\n\tchain input {\n\t}\n\tchain forward {\n\t}\n}\n"), 0o644)
	if s := nftablesAtBoot(); !strings.Contains(s, "enabled at boot, 2 chains in /etc/nftables.conf") {
		t.Errorf("got %q", s)
	}
}

// A drop-in folder sshd reads as root but this user cannot (Rocky's
// sshd_config.d is 0700) leaves the SSH settings unknown: no warning from the
// main file's lines, one info instead. Readable, the drop-in's no holds.
func TestSSHDropInUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	dir := t.TempDir()
	old := sshdConfig
	defer func() { sshdConfig = old }()
	sshdConfig = filepath.Join(dir, "sshd_config")
	os.WriteFile(sshdConfig, []byte("Include sshd_config.d/*.conf\nPasswordAuthentication yes\nPermitRootLogin yes\n"), 0o644)
	d := filepath.Join(dir, "sshd_config.d")
	os.Mkdir(d, 0o755)
	drop := filepath.Join(d, "50-cloud-init.conf")
	os.WriteFile(drop, []byte("PasswordAuthentication no\nPermitRootLogin no\n"), 0o644)
	risks := func() map[string]string {
		ssh, _, unread := sshdSettings()
		out := map[string]string{}
		for _, r := range sshRisks(ssh, unread) {
			out[r.Key] = r.Severity
		}
		return out
	}
	if got := risks(); len(got) != 0 {
		t.Errorf("readable drop-in with no: %v", got)
	}
	os.Chmod(drop, 0)
	if got := risks(); len(got) != 1 || got["ssh:unreadable"] != "info" {
		t.Errorf("unreadable drop-in file: %v", got)
	}
	ssh, _, unread := sshdSettings()
	if r := sshRisks(ssh, unread); len(r) != 1 || !strings.Contains(r[0].Summary, "run Shentu as root") || !Unchecked(r[0]) {
		t.Errorf("permission: %+v", r)
	}
	os.Chmod(drop, 0o644)
	os.Chmod(d, 0)
	defer os.Chmod(d, 0o755)
	if got := risks(); len(got) != 1 || got["ssh:unreadable"] != "info" {
		t.Errorf("unreadable drop-in folder: %v", got)
	}
	os.Chmod(d, 0o755)
	// Another error than permission is told as it is, not as "run as root".
	os.Chmod(drop, 0o644)
	os.Remove(drop)
	os.Mkdir(drop, 0o755) // a folder where the file was: "is a directory"
	ssh, _, unread = sshdSettings()
	if r := sshRisks(ssh, unread); len(r) != 1 || strings.Contains(r[0].Summary, "root") || !strings.Contains(r[0].Summary, "is a directory") {
		t.Errorf("other error: %+v", r)
	}
	os.Remove(drop)
	// Without an Include, the main file's yes is a warning as before.
	os.WriteFile(sshdConfig, []byte("PasswordAuthentication yes\nPermitRootLogin yes\n"), 0o644)
	if got := risks(); got["ssh:password"] != "warning" || got["ssh:root"] != "warning" || len(got) != 2 {
		t.Errorf("main file only: %v", got)
	}
}
