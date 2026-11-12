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
