package hostenv

import "context"

// CollectorVersion is stamped into every Facts.
const CollectorVersion = "0.1.0"

// Collector turns what a Source returns into Facts for one platform family.
// Collectors never touch the OS directly, so replaying a fixture exercises
// exactly the code that runs live.
type Collector interface {
	Name() string
	// Allowlist is every command the collector may run, as exact argv.
	Allowlist() [][]string
	Collect(ctx context.Context, src Source) *Facts
}

// ForOS picks the collector for a GOOS. The choice is made at run time from
// Source.Info, so a Linux fixture replays through the Linux collector on any
// machine; build tags are reserved for Sources that call platform APIs.
func ForOS(goos string) Collector {
	switch goos {
	case "linux":
		return LinuxCollector{}
	case "windows":
		return WindowsCollector{}
	}
	return Unsupported{GOOS: goos}
}

// Collect is the usual entry point: the collector for src's OS, run once.
func Collect(ctx context.Context, src Source) *Facts {
	return ForOS(src.Info().GOOS).Collect(ctx, src)
}

// Unsupported reports every fact as unknown for a platform without a
// collector yet, so checks print "cannot tell" instead of a clean bill.
type Unsupported struct{ GOOS string }

func (u Unsupported) Name() string          { return "unsupported-" + u.GOOS }
func (u Unsupported) Allowlist() [][]string { return nil }

func (u Unsupported) Collect(_ context.Context, src Source) *Facts {
	f := NewFacts(u.Name(), CollectorVersion, src.Info().RecordedAt)
	r, d := ReasonUnsupported, "no hostenv collector for "+u.GOOS+" yet"
	f.Platform = Obs[Platform]{Status: StatusPartial, Reason: r, Detail: d, Value: Platform{OS: u.GOOS, Arch: src.Info().GOARCH}}
	f.Privilege = OK(Privilege{Elevated: src.Info().Elevated})
	f.Packages, f.Patches, f.Services = Unknown[PackageSet](r, d), Unknown[[]Patch](r, d), Unknown[[]Service](r, d)
	f.Processes, f.Accounts, f.Listeners = Unknown[[]Process](r, d), Unknown[[]Account](r, d), Unknown[[]Listener](r, d)
	f.Persistence, f.Firewall = Unknown[[]PersistenceItem](r, d), Unknown[Firewall](r, d)
	f.RemoteAccess = RemoteAccess{SSH: Unknown[SSHConfig](r, d), RDP: Unknown[RDPConfig](r, d),
		WinRM: Unknown[WinRMConfig](r, d), SMB: Unknown[SMBConfig](r, d)}
	f.Antimalware, f.AuthEvents, f.Web = Unknown[Antimalware](r, d), Unknown[AuthEvents](r, d), Unknown[Web](r, d)
	return f
}
