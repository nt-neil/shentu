//go:build !windows

package main

import (
	"context"
	"errors"

	"github.com/nt-neil/shentu/tools"
)

// serviceCommand is Windows only: on Linux the systemd units in packaging/
// run patrol and the daily report.
func serviceCommand(context.Context, *Config, *tools.Env, []string) error {
	return errors.New("shentu service is for Windows; on Linux the systemd units (shentu-patrol.timer, shentu-daily.timer) run patrol")
}
