//go:build windows

package main

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// programData is %ProgramData% (C:\ProgramData), from the known folder.
func programData() string {
	if p, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0); err == nil && p != "" {
		return p
	}
	if p := os.Getenv("ProgramData"); p != "" {
		return p
	}
	return `C:\ProgramData`
}

// defaultConfigPath is %ProgramData%\Shentu\shentu.toml: config and state
// both live under %ProgramData%\Shentu, whose ACL admits only SYSTEM and
// Administrators.
func defaultConfigPath() string { return filepath.Join(programData(), "Shentu", "shentu.toml") }

// osDefaults replaces the Unix paths in the defaults with their Windows
// counterparts. Logon events come from the event log, not from files.
func osDefaults(c *Config) {
	pd := programData()
	c.StateDir = filepath.Join(pd, "Shentu", "state")
	c.Tools.LogPaths = nil
	c.Tools.WatchPaths = []string{`C:\inetpub\wwwroot`, filepath.Join(pd, `Microsoft\Windows\Start Menu\Programs\StartUp`)}
	c.Tools.WebUsers = nil // web shells under IIS are found by their w3wp.exe parent (checks), not by account
	c.Tools.AppPaths = []string{`C:\inetpub`}
}

// stateSDDL is the DACL of %ProgramData%\Shentu and the state directory:
// protected (no inherited entries), full control for SYSTEM and the
// Administrators group only, inherited by everything created inside.
const stateSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// secureDir creates dir and replaces its DACL with stateSDDL.
func secureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(stateSDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// ensureStateDir secures %ProgramData%\Shentu (config, env file with
// tokens, state) and the state directory, wherever it is configured.
// Setting the ACL needs an elevated process, as the service runs.
func ensureStateDir(dir string) error {
	if err := secureDir(filepath.Join(programData(), "Shentu")); err != nil {
		return err
	}
	return secureDir(dir)
}
