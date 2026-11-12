package tools

// Site survey: what this server is, before judging what is unusual on it. Like a
// guard who walks the premises first: services and who can reach them, web and app
// stacks, databases, firewall, SSH settings, containers, cron and login accounts.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

var siteProfile = Tool{
	Name:        "site_profile",
	Description: "Surveys the server: OS, running services and whether they listen on all interfaces, web servers, app stacks, databases, firewall, effective SSH settings, containers, cron files and login accounts, plus the risks that follow from them (e.g. a database reachable from the network). Use it first to understand the environment.",
	Params:      schema(`{"type":"object","properties":{}}`),
	Run: func(ctx context.Context, env *Env, args json.RawMessage) (any, error) {
		return Survey(ctx, env), nil
	},
}

// Service is one program that listens on the network.
type Service struct {
	Name   string   `json:"name"`
	Role   string   `json:"role"`
	Ports  []string `json:"ports"`
	Public bool     `json:"public"` // listens on a non-loopback address
}

// Risk is a finding that follows from the configuration itself.
type Risk struct {
	Key      string `json:"key"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
}

// uncheckedRisks are the risks that say a check could not tell (a file it
// needs could not be read): reports list them apart, every time, and never
// push them as alerts.
var uncheckedRisks = map[string]bool{"ssh:unreadable": true}

// Unchecked reports whether r says a check could not tell.
func Unchecked(r Risk) bool { return uncheckedRisks[r.Key] }

// SiteProfile is the survey result. It is stored by patrol as the baseline.
type SiteProfile struct {
	Time          time.Time         `json:"time"`
	OS            string            `json:"os"`
	Kernel        string            `json:"kernel"`
	Services      []Service         `json:"services"`
	Stacks        []string          `json:"app_stacks,omitempty"`
	Lockfiles     []string          `json:"lock_files,omitempty"`
	Firewall      string            `json:"firewall"`
	SSH           map[string]string `json:"ssh"`
	SSHHash       string            `json:"ssh_config_hash"`
	Containers    []string          `json:"containers,omitempty"`
	CronFiles     []string          `json:"cron_files"`
	LoginAccounts []string          `json:"login_accounts"`
	Risks         []Risk            `json:"risks,omitempty"`
}

var roles = map[string]string{
	"nginx": "web server", "apache2": "web server", "httpd": "web server", "caddy": "web server", "lighttpd": "web server",
	"mysqld": "database (MySQL)", "mariadbd": "database (MariaDB)", "postgres": "database (PostgreSQL)",
	"mongod": "database (MongoDB)", "redis-server": "cache (Redis)", "memcached": "cache (Memcached)",
	"node": "app (Node.js)", "python3": "app (Python)", "python": "app (Python)", "gunicorn": "app (Python)",
	"uwsgi": "app (Python)", "java": "app (Java)", "ruby": "app (Ruby)", "puma": "app (Ruby)",
	"dockerd": "containers (Docker)", "docker-proxy": "containers (Docker)", "containerd": "containers",
	"sshd": "SSH", "named": "DNS", "unbound": "DNS", "systemd-resolve": "DNS (local)", "master": "mail",
	"exim4": "mail", "sendmail": "mail", "vsftpd": "FTP", "proftpd": "FTP", "smbd": "file sharing (SMB)",
	"ollama": "local LLM", "chronyd": "time", "rpcbind": "RPC", "avahi-daemon": "mDNS",
	"systemd-network": "network (DHCP)", "dhclient": "network (DHCP)", "NetworkManager": "network",
}

// riskyIfPublic are services that should rarely be reachable from other machines.
var riskyIfPublic = map[string]bool{"mysqld": true, "mariadbd": true, "postgres": true, "mongod": true,
	"redis-server": true, "memcached": true, "rpcbind": true, "smbd": true}

// Survey builds the profile. It only reads; nothing is changed.
func Survey(ctx context.Context, env *Env) SiteProfile {
	p := SiteProfile{Time: time.Now().UTC(), Firewall: firewall(ctx)}
	osr := osRelease()
	p.OS = osr["PRETTY_NAME"]
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		p.Kernel = strings.TrimSpace(string(b))
	}

	by := map[string]*Service{}
	if ports, err := ListeningPorts(); err == nil {
		for _, pt := range ports {
			name := pt.Process
			if name == "" {
				name = "unknown"
			}
			if strings.HasPrefix(name, "php-fpm") {
				name = "php-fpm"
			}
			s := by[name]
			if s == nil {
				role := roles[name]
				if name == "php-fpm" {
					role = "app (PHP)"
				}
				if role == "" {
					role = "other"
				}
				s = &Service{Name: name, Role: role}
				by[name] = s
			}
			s.Ports = append(s.Ports, fmt.Sprintf("%s/%d", pt.Proto, pt.Port))
			if ip := net.ParseIP(pt.Addr); ip != nil && !ip.IsLoopback() {
				s.Public = true
			}
		}
	}
	for _, s := range by {
		sort.Strings(s.Ports)
		s.Ports = dedupe(s.Ports)
		p.Services = append(p.Services, *s)
		if s.Public && riskyIfPublic[s.Name] {
			p.Risks = append(p.Risks, Risk{"exposed:" + s.Name, "critical",
				fmt.Sprintf("%s (%s) listens on all interfaces (%s); bind it to 127.0.0.1 or firewall it", s.Name, s.Role, strings.Join(s.Ports, ", "))})
		}
	}
	sort.Slice(p.Services, func(i, j int) bool { return p.Services[i].Name < p.Services[j].Name })

	stacks := map[string]bool{}
	for _, l := range FindLockfiles(env.AppPaths) {
		stacks[l.Ecosystem] = true
		if len(p.Lockfiles) < 20 {
			p.Lockfiles = append(p.Lockfiles, l.Path)
		}
	}
	for s := range stacks {
		p.Stacks = append(p.Stacks, s)
	}
	sort.Strings(p.Stacks)

	var unread []string
	p.SSH, p.SSHHash, unread = sshdSettings()
	p.Risks = append(p.Risks, sshRisks(p.SSH, unread)...)
p.Risks = append(p.Risks, apacheH2Risk(ctx, apacheConfGlob)...)
	if p.Firewall == "none detected" && hasPublic(p.Services) {
		p.Risks = append(p.Risks, Risk{"firewall:none", "info", "no host firewall detected (nftables, ufw, firewalld); fine only if a cloud firewall covers this server"})
	}

	for _, sock := range []string{"/run/docker.sock", "/var/run/docker.sock"} {
		if st, err := os.Stat(sock); err == nil {
			p.Containers = append(p.Containers, "docker")
			if st.Mode().Perm()&0o002 != 0 {
				p.Risks = append(p.Risks, Risk{"docker:socket", "critical", sock + " is writable by every user, which gives them root"})
			}
			break
		}
	}
	if _, err := os.Stat("/run/podman"); err == nil {
		p.Containers = append(p.Containers, "podman")
	}
	p.CronFiles = cronFiles()
	p.LoginAccounts = AccountsAudit().LoginAccounts
	return p
}

func hasPublic(s []Service) bool {
	for _, x := range s {
		if x.Public {
			return true
		}
	}
	return false
}

func dedupe(s []string) []string {
	var out []string
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func firewall(ctx context.Context) string {
	if b, err := os.ReadFile("/etc/ufw/ufw.conf"); err == nil && strings.Contains(string(b), "ENABLED=yes") {
		return "ufw (enabled)"
	}
	if comm := findProcess("firewalld"); comm {
		return "firewalld (running)"
	}
	if out, err := exec.CommandContext(ctx, "nft", "list", "ruleset").Output(); err == nil {
		chains := strings.Count(string(out), "chain ")
		if chains > 0 {
			return fmt.Sprintf("nftables (%d chains)", chains)
		}
	} else if !errors.Is(err, exec.ErrNotFound) {
		// Patrol's sandbox has no CAP_NET_ADMIN, so it cannot list the ruleset; the boot config is readable.
		if s := nftablesAtBoot(); s != "" {
			return s
		}
		return "no firewall enabled at boot (nftables.service is off); rules added at runtime cannot be read here, ask in chat"
	}
	if out, err := exec.CommandContext(ctx, "iptables", "-S").Output(); err == nil && strings.Count(string(out), "\n") > 3 {
		return "iptables rules present"
	}
	return "none detected"
}

// nftablesRoot is "/" except in tests.
var nftablesRoot = "/"

// nftablesAtBoot describes the nftables rules loaded at boot, read from the config files, which needs no privilege.
func nftablesAtBoot() string {
	enabled := false
	for _, d := range []string{"etc/systemd/system/multi-user.target.wants", "etc/systemd/system/sysinit.target.wants"} {
		if _, err := os.Stat(filepath.Join(nftablesRoot, d, "nftables.service")); err == nil {
			enabled = true
		}
	}
	if !enabled {
		return ""
	}
	for _, c := range []string{"etc/nftables.conf", "etc/sysconfig/nftables.conf"} {
		if b, err := os.ReadFile(filepath.Join(nftablesRoot, c)); err == nil {
			return fmt.Sprintf("nftables (enabled at boot, %d chains in /%s; live rules: ask in chat)", strings.Count(string(b), "chain "), c)
		}
	}
	return "nftables (enabled at boot; live rules: ask in chat)"
}

func findProcess(name string) bool {
	for _, pid := range pids() {
		if comm(pid) == name {
			return true
		}
	}
	return false
}

// sshdConfig is the sshd configuration read; relative Include paths are under its folder.
var sshdConfig = "/etc/ssh/sshd_config"

// sshRisks are the risks of the sshd settings. A setting a file that could not
// be read may have set ("unknown") is not judged: it is reported as unknown.
func sshRisks(ssh map[string]string, unread []string) []Risk {
	var out []Risk
	if ssh["passwordauthentication"] == "yes" {
		out = append(out, Risk{"ssh:password", "warning", "SSH accepts passwords (PasswordAuthentication yes); key-only login stops brute force"})
	}
	if ssh["permitrootlogin"] == "yes" {
		out = append(out, Risk{"ssh:root", "warning", "SSH allows root to log in with a password (PermitRootLogin yes)"})
	}
	if ssh["passwordauthentication"] == "unknown" || ssh["permitrootlogin"] == "unknown" {
		why := "; check that the files are there and readable"
		if slices.ContainsFunc(unread, func(u string) bool { return strings.HasSuffix(u, "(permission denied)") }) {
			why = "; run Shentu as root, as sshd reads them"
		}
		out = append(out, Risk{"ssh:unreadable", "info", "cannot tell the SSH settings (PasswordAuthentication, PermitRootLogin): " +
			strings.Join(unread, ", ") + " could not be read" + why})
	}
	return out
}

// sshdFields splits one sshd_config line into its keyword and arguments: the
// keyword ends at the first white space or "=", which may have white space
// around it (PermitRootLogin=yes, PasswordAuthentication = yes), as in sshd.
func sshdFields(line string) []string {
	line = strings.TrimSpace(line)
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return []string{line}
	}
	rest := strings.TrimLeft(line[i:], " \t")
	if strings.HasPrefix(rest, "=") {
		rest = rest[1:]
	}
	return append([]string{line[:i]}, strings.Fields(rest)...)
}

// sshdSettings returns the effective global sshd settings that matter for security,
// following Include in place; the first value wins, as in sshd. Match blocks are not
// evaluated. The hash covers every line read, to notice any change. A file or
// Include folder that cannot be read (sshd reads it as root) leaves every setting
// not set before it "unknown"; unread lists them.
func sshdSettings() (map[string]string, string, []string) {
	want := map[string]string{"port": "22", "permitrootlogin": "prohibit-password", "passwordauthentication": "yes",
		"pubkeyauthentication": "yes", "permitemptypasswords": "no", "x11forwarding": "no"}
	got := map[string]bool{}
	h := sha256.New()
	var unread []string
	unknown := func(path string, err error) {
		why := err.Error()
		if errors.Is(err, fs.ErrPermission) { // EACCES, EPERM
			why = "permission denied"
		} else if pe := (*fs.PathError)(nil); errors.As(err, &pe) {
			why = pe.Err.Error()
		}
		unread = append(unread, path+" ("+why+")")
		for k := range want {
			if !got[k] {
				want[k], got[k] = "unknown", true
			}
		}
	}
	var read func(path string, depth int) bool // false stops at a Match block
	read = func(path string, depth int) bool {
		if depth > 4 {
			return true
		}
		b, err := os.ReadFile(path)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				unknown(path, err)
			}
			return true
		}
		h.Write(b)
		for _, line := range strings.Split(string(b), "\n") {
			f := sshdFields(line)
			if len(f) < 2 || strings.HasPrefix(f[0], "#") {
				continue
			}
			key := strings.ToLower(f[0])
			if key == "match" {
				return false
			}
			if key == "include" {
				for _, pat := range f[1:] {
					if !filepath.IsAbs(pat) {
						pat = filepath.Join(filepath.Dir(sshdConfig), pat)
					}
					// Glob says nothing of a folder it cannot list.
					if _, err := os.ReadDir(filepath.Dir(pat)); err != nil && !errors.Is(err, fs.ErrNotExist) {
						unknown(filepath.Dir(pat), err)
					}
					files, _ := filepath.Glob(pat)
					sort.Strings(files)
					for _, inc := range files {
						if !read(inc, depth+1) {
							return false
						}
					}
				}
				continue
			}
			if _, ok := want[key]; ok && !got[key] {
				want[key], got[key] = strings.ToLower(f[1]), true
			}
		}
		return true
	}
	read(sshdConfig, 0)
	return want, hex.EncodeToString(h.Sum(nil))[:16], unread
}

func cronFiles() []string {
	var out []string
	for _, pat := range []string{"/etc/crontab", "/etc/cron.d/*", "/var/spool/cron/crontabs/*", "/var/spool/cron/*"} {
		files, _ := filepath.Glob(pat)
		for _, f := range files {
			if st, err := os.Stat(f); err == nil && st.Mode().IsRegular() {
				out = append(out, f)
			}
		}
	}
	sort.Strings(out)
	return out
}

var safeName = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// Brief is a short text version of the profile for the model's system prompt.
func (p SiteProfile) Brief() string {
	var b strings.Builder
	fmt.Fprintf(&b, "OS: %s, kernel %s. Firewall: %s.\n", p.OS, p.Kernel, p.Firewall)
	// Process names can be chosen by anyone who runs a program, so only names from the
	// known roles table reach the prompt; the rest are counted.
	b.WriteString("Services:")
	other := 0
	for _, s := range p.Services {
		if _, known := roles[s.Name]; !known && s.Name != "php-fpm" {
			other++
			continue
		}
		where := "local only"
		if s.Public {
			where = "network"
		}
		fmt.Fprintf(&b, " %s (%s, %s);", s.Name, s.Role, where)
	}
	if other > 0 {
		fmt.Fprintf(&b, " %d other service(s), see site_profile;", other)
	}
	if len(p.Stacks) > 0 {
		fmt.Fprintf(&b, "\nApp stacks: %s.", strings.Join(p.Stacks, ", "))
	}
	fmt.Fprintf(&b, "\nSSH: port %s, PermitRootLogin %s, PasswordAuthentication %s.", p.SSH["port"], p.SSH["permitrootlogin"], p.SSH["passwordauthentication"])
	if len(p.Containers) > 0 {
		fmt.Fprintf(&b, "\nContainers: %s.", strings.Join(p.Containers, ", "))
	}
	var accounts []string
	for _, a := range p.LoginAccounts {
		if safeName.MatchString(a) {
			accounts = append(accounts, a)
		}
	}
	fmt.Fprintf(&b, "\nLogin accounts: %s.", strings.Join(accounts, ", "))
	return b.String()
}

// Drift compares a new survey with the stored baseline.
func Drift(old, now SiteProfile) []Risk {
	var out []Risk
	if old.Time.IsZero() {
		return nil
	}
	if old.SSHHash != "" && now.SSHHash != old.SSHHash {
		out = append(out, Risk{"drift:ssh:" + now.SSHHash, "warning", "SSH server configuration changed since the last survey"})
	}
	for _, a := range diff(now.LoginAccounts, old.LoginAccounts) {
		out = append(out, Risk{"drift:account:" + a, "warning", "new login account since the last survey: " + a})
	}
	for _, f := range diff(now.CronFiles, old.CronFiles) {
		out = append(out, Risk{"drift:cron:" + f, "warning", "new cron file since the last survey: " + f})
	}
	return out // new services already show up as new listening ports
}

func diff(now, old []string) []string {
	seen := map[string]bool{}
	for _, v := range old {
		seen[v] = true
	}
	var out []string
	for _, v := range now {
		if !seen[v] {
			out = append(out, v)
		}
	}
	return out
}
