package hostenv

// The host firewall on Linux, as tools/survey.go described it before
// Phase 1c: ufw's config, a running firewalld, the live nftables ruleset,
// nftables enabled at boot (readable without CAP_NET_ADMIN), iptables.
// The description tools printed is kept in Extra["summary"].

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
)

var (
	nftListArgv  = []string{"/usr/sbin/nft", "list", "ruleset"}
	iptablesArgv = []string{"/usr/sbin/iptables", "-S"}
	iptablesSbin = []string{"/sbin/iptables", "-S"} // Alpine
)

func init() {
	registerBig(nftListArgv, 64<<20, MaxTimeout) // fail2ban sets can be large
}

// Firewall works out the active host firewall. processes is the processes
// fact (for firewalld); nil skips that test.
func (c LinuxCollector) Firewall(ctx context.Context, src Source, processes []Process) Obs[Firewall] {
	fw := func(backend string, enabled bool, summary string) Firewall {
		return Firewall{Backend: backend, Enabled: enabled, Extra: map[string]string{"summary": summary}}
	}
	if b, err := src.ReadFile("/etc/ufw/ufw.conf"); err == nil && strings.Contains(string(b), "ENABLED=yes") {
		return OK(fw("ufw", true, "ufw (enabled)"))
	}
	for _, p := range processes {
		if p.Name == "firewalld" {
			return OK(fw("firewalld", true, "firewalld (running)"))
		}
	}
	res, err := src.Run(ctx, nftListArgv)
	switch {
	case err == nil && res.ExitCode == 0:
		if chains := strings.Count(string(res.Stdout), "chain "); chains > 0 {
			return OK(fw("nftables", true, fmt.Sprintf("nftables (%d chains)", chains)))
		}
	case !errors.Is(err, fs.ErrNotExist):
		// Patrol's sandbox has no CAP_NET_ADMIN, so it cannot list the
		// ruleset; the boot config is readable.
		if s := c.NftablesAtBoot(src); s != "" {
			return Partial(fw("nftables", true, s), ReasonPermission, "live nftables rules unreadable; boot configuration read instead")
		}
		return Partial(fw("nftables", false, "no firewall enabled at boot (nftables.service is off); rules added at runtime cannot be read here, ask in chat"),
			ReasonPermission, "live nftables rules unreadable")
	}
	out, err := src.Run(ctx, iptablesArgv)
	if errors.Is(err, fs.ErrNotExist) {
		out, err = src.Run(ctx, iptablesSbin)
	}
	if err == nil && out.ExitCode == 0 && strings.Count(string(out.Stdout), "\n") > 3 {
		return OK(fw("iptables", true, "iptables rules present"))
	}
	return OK(fw("", false, "none detected"))
}

// NftablesAtBoot describes the nftables rules loaded at boot, read from
// the config files (no privilege needed); "" when nftables.service is not
// enabled.
func (LinuxCollector) NftablesAtBoot(src Source) string {
	enabled := false
	for _, d := range []string{"/etc/systemd/system/multi-user.target.wants", "/etc/systemd/system/sysinit.target.wants"} {
		if exists(src, d+"/nftables.service") {
			enabled = true
		}
	}
	if !enabled {
		return ""
	}
	for _, c := range []string{"/etc/nftables.conf", "/etc/sysconfig/nftables.conf"} {
		if b, err := src.ReadFile(c); err == nil {
			return fmt.Sprintf("nftables (enabled at boot, %d chains in %s; live rules: ask in chat)", strings.Count(string(b), "chain "), c)
		}
	}
	return "nftables (enabled at boot; live rules: ask in chat)"
}
