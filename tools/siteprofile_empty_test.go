package tools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// S-173r3-1: on a host where nothing can be read (a replay with no
// entries: every read and command is "not recorded"), site_profile's data
// fields, the ones the main package's M1 test judges (toolData there),
// stay empty or say they could not be read: the SSH settings "unknown",
// risks only "cannot tell" ones (key ...:unreadable). A reader that puts a fixed fallback value in one of them
// would make an unread host look as if something were read; firewall is
// not among them for that reason (N-173r2-1). Run for macOS and Linux.
func TestSiteProfileEmptyHost(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			dir := t.TempDir()
			manifest := `{"format":"` + hostenv.FixtureFormat + `","info":{"goos":"` + goos + `","goarch":"arm64","elevated":false,"recorded_at":"2026-11-22T00:00:00Z"},"entries":[]}`
			if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o600); err != nil {
				t.Fatal(err)
			}
			os.Mkdir(filepath.Join(dir, "blobs"), 0o700)
			rp, err := hostenv.LoadReplay(dir)
			if err != nil {
				t.Fatal(err)
			}
			withHost(t, rp)
			p := Survey(context.Background(), &Env{})
			for name, empty := range map[string]bool{
				"services":       len(p.Services) == 0,
				"app_stacks":     len(p.Stacks) == 0,
				"lock_files":     len(p.Lockfiles) == 0,
				"ssh":            sshAllUnknown(p.SSH),
				"containers":     len(p.Containers) == 0,
				"cron_files":     len(p.CronFiles) == 0,
				"login_accounts": len(p.LoginAccounts) == 0,
				"risks":          risksAllUnreadable(p.Risks),
			} {
				if !empty {
					var keys []string // risk keys are fixed words, never this host's
					for _, r := range p.Risks {
						keys = append(keys, r.Key)
					}
					t.Errorf("%s holds a value on a host where nothing could be read (risk keys %v)", name, keys)
				}
			}
		})
	}
}

// sshAllUnknown: no setting, or each one "unknown" (said, not a value read).
func sshAllUnknown(m map[string]string) bool {
	for _, v := range m {
		if v != "unknown" {
			return false
		}
	}
	return true
}

// risksAllUnreadable: no risk, or only ones saying what could not be read.
func risksAllUnreadable(rs []Risk) bool {
	for _, r := range rs {
		if !strings.HasSuffix(r.Key, ":unreadable") {
			return false
		}
	}
	return true
}
