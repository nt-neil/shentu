//go:build !windows

package main

import "os"

// defaultConfigPath is where the configuration lives unless SHENTU_CONFIG says otherwise.
func defaultConfigPath() string { return "/etc/shentu/shentu.toml" }

// osDefaults adjusts the built-in defaults for the OS; Unix keeps them as set.
func osDefaults(*Config) {}

// ensureStateDir creates the state directory, readable by its owner only.
func ensureStateDir(dir string) error { return os.MkdirAll(dir, 0o700) }
