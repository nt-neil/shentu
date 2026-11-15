//go:build !windows

package main

import (
	"errors"
	"os"
)

// defaultConfigPath is where the configuration lives unless SHENTU_CONFIG says otherwise.
func defaultConfigPath() string { return "/etc/shentu/shentu.toml" }

// osDefaults adjusts the built-in defaults for the OS; Unix keeps them as set.
func osDefaults(*Config) {}

// ensureStateDir creates the state directory, readable by its owner only.
func ensureStateDir(dir string) error { return os.MkdirAll(dir, 0o700) }

// trustConfig decides whether the configuration may be read; on Unix the
// files' own modes and /etc's ownership already decide that.
func trustConfig(string) (load bool, err error) { return true, nil }

// trustSkills is true on Unix: the config folder's mode decides.
func trustSkills(string) bool { return true }

// privileged reports a process that may read everything Shentu checks.
func privileged() bool { return os.Geteuid() == 0 }

// privilegeError is what a command that changes the state says without it.
func privilegeError(what string) error {
	return errors.New(what + " changes /var/lib/shentu; run it with sudo")
}

// unprivilegedNote is chat's warning without it.
const unprivilegedNote = "note: not running as root; some logs and process details will be unreadable and block_ip will fail."

// How the bot is (re)started: the shentu-bot systemd service.
const (
	botRestartHint = "Start the service: sudo systemctl restart shentu-bot"
	botRunningHint = "The bot service must be running (systemctl start shentu-bot)"
)

// stateReady is checked before chat and bot; on Unix a state directory
// that cannot be made only turns the audit log off, as before.
func stateReady(string) error { return nil }
