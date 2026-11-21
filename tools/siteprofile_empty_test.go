package tools

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// S-173r3-1: on a host where nothing can be read (a replay with no
// entries: every read and command is "not recorded"), site_profile's data
// fields, the ones the main package's M1 test judges (toolData there),
// stay empty. A reader that puts a fixed fallback value in one of them
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
				"ssh":            len(p.SSH) == 0,
				"containers":     len(p.Containers) == 0,
				"cron_files":     len(p.CronFiles) == 0,
				"login_accounts": len(p.LoginAccounts) == 0,
				"risks":          len(p.Risks) == 0,
			} {
				if !empty {
					t.Errorf("%s is not empty on a host where nothing could be read", name)
				}
			}
		})
	}
}
