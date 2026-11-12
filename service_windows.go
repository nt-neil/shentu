//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nt-neil/shentu/tools"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// Two services, like the systemd units on Linux, each stopped, started and
// restarted on its own, both LocalSystem (reading the Security log and the
// task store needs it), both read-only: the Windows MVP takes no action.
type svcSpec struct {
	name, display, desc string
	runArgs             []string // the service command line after the binary
	flag                string   // "" or "--bot", for messages
}

var (
	patrolSpec = svcSpec{"Shentu", "Shentu security patrol",
		"Read-only security patrol: Windows facts, checks, MSRC/KEV, IIS code audit; reports by the configured notifier.",
		[]string{"service", "run"}, ""}
	// The bot's token stays in the protected configuration under
	// %ProgramData%\Shentu: never in the service's command line, never in
	// the event log (see logf).
	botSpec = svcSpec{"ShentuBot", "Shentu Telegram bot",
		"Answers the paired user on Telegram; reads the configuration under %ProgramData%\\Shentu.",
		[]string{"service", "run", "--bot"}, " --bot"}
)

const serviceUsage = "usage: shentu service install|uninstall|start|stop|status [--bot]"

func serviceCommand(ctx context.Context, cfg *Config, env *tools.Env, args []string) error {
	sp := patrolSpec
	if len(args) == 2 && args[1] == "--bot" {
		sp, args = botSpec, args[:1]
	}
	if len(args) != 1 {
		return errors.New(serviceUsage)
	}
	switch args[0] {
	case "install":
		return installService(cfg, sp)
	case "uninstall":
		return uninstallService(sp)
	case "start":
		return withService(sp, func(s *mgr.Service) error { return s.Start() })
	case "stop":
		return withService(sp, func(s *mgr.Service) error { return stopService(s) })
	case "status":
		return withService(sp, func(s *mgr.Service) error {
			st, err := s.Query()
			if err == nil {
				fmt.Println(stateName(st.State))
			}
			return err
		})
	case "run":
		return runService(cfg, env, sp)
	}
	return errors.New(serviceUsage)
}

// binSDDL is the folder of the service binary: owner Administrators,
// full control for SYSTEM and Administrators, read and execute for Users,
// nothing inherited (no CREATOR OWNER entry for whoever made the folder).
const binSDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"

// installService registers shentu.exe as an automatic (delayed) service
// running as LocalSystem, restarted on failure. Any user who could replace
// the binary would run code as SYSTEM, so it must sit in
// %ProgramFiles%\Shentu: that folder (and the binary, by inheritance) gets
// binSDDL, then passes the strict check. A binary anywhere else is
// refused rather than having the permissions of an unrelated folder
// changed.
func installService(cfg *Config, sp svcSpec) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.Abs(exe); err != nil {
		return err
	}
	pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return err
	}
	want := filepath.Join(pf, "Shentu")
	if !strings.EqualFold(filepath.Dir(exe), want) {
		return fmt.Errorf("install from %s: copy shentu.exe there (as an administrator) and run %s service install%s",
			want, filepath.Join(want, "shentu.exe"), sp.flag)
	}
	if err := lockBinaryFolder(want, exe); err != nil {
		return err
	}
	for _, p := range []string{want, exe} {
		if err := checkTrustedAs(p, false); err != nil {
			return fmt.Errorf("%w; the service binary must be writable by administrators only", err)
		}
	}
	if err := ensureStateDir(cfg.StateDir); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(sp.name); err == nil {
		s.Close()
		return fmt.Errorf("the %s service is already installed; uninstall it first to reinstall", sp.name)
	}
	s, err := m.CreateService(sp.name, exe, mgr.Config{
		DisplayName: sp.display, Description: sp.desc,
		StartType: mgr.StartAutomatic, DelayedAutoStart: true, // LocalSystem: no ServiceStartName
	}, sp.runArgs...)
	if err != nil {
		return err
	}
	defer s.Close()
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: time.Minute}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, uint32((24 * time.Hour).Seconds())); err != nil {
		s.Delete()
		return err
	}
	// Restart also when the service stops with an error, not only on a crash.
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		s.Delete()
		return err
	}
	if err := eventlog.InstallAsEventCreate(sp.name, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) &&
		!alreadyRegistered(err) {
		s.Delete()
		return err
	}
	fmt.Printf("installed the %s service (automatic, LocalSystem); start it with: shentu service start%s\n", sp.name, sp.flag)
	return nil
}

// lockBinaryFolder applies binSDDL to the folder and re-applies inherited
// security to the binary (dropping any explicit entry it carries).
func lockBinaryFolder(dir, exe string) error {
	if fi, err := os.Lstat(dir); err != nil || fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
		return fmt.Errorf("%s must be a plain folder", dir)
	}
	sd, err := windows.SecurityDescriptorFromString(binSDDL)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, dacl, nil); err != nil {
		return fmt.Errorf("securing %s: %w", dir, err)
	}
	// An empty DACL, unprotected: the binary keeps only what it inherits.
	esd, err := windows.SecurityDescriptorFromString("D:")
	if err != nil {
		return err
	}
	empty, _, err := esd.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(exe, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, owner, nil, empty, nil); err != nil {
		return fmt.Errorf("securing %s: %w", exe, err)
	}
	return nil
}

// alreadyRegistered recognises eventlog's "<source> registry key already
// exists" (a plain error in x/sys): the source stays from an earlier install.
func alreadyRegistered(err error) bool {
	return err != nil && strings.Contains(err.Error(), "registry key already exists")
}

func uninstallService(sp svcSpec) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(sp.name)
	if err != nil {
		return fmt.Errorf("the %s service is not installed: %w", sp.name, err)
	}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		if err := stopService(s); err != nil {
			return err
		}
	}
	if err := s.Delete(); err != nil {
		return err
	}
	eventlog.Remove(sp.name)
	fmt.Printf("removed the %s service; configuration and state in %s are kept\n", sp.name, filepath.Dir(defaultConfigPath()))
	return nil
}

func withService(sp svcSpec, f func(*mgr.Service) error) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(sp.name)
	if err != nil {
		return fmt.Errorf("the %s service is not installed: %w", sp.name, err)
	}
	defer s.Close()
	return f(s)
}

// stopService asks the service to stop and waits up to 30 s for it.
func stopService(s *mgr.Service) error {
	st, err := s.Control(svc.Stop)
	if err != nil {
		return err
	}
	for deadline := time.Now().Add(30 * time.Second); st.State != svc.Stopped; {
		if time.Now().After(deadline) {
			return errors.New("the service did not stop within 30 s")
		}
		time.Sleep(300 * time.Millisecond)
		if st, err = s.Query(); err != nil {
			return err
		}
	}
	return nil
}

func stateName(s svc.State) string {
	return map[svc.State]string{svc.Stopped: "stopped", svc.StartPending: "starting", svc.StopPending: "stopping",
		svc.Running: "running", svc.ContinuePending: "resuming", svc.PausePending: "pausing", svc.Paused: "paused"}[s]
}

// runService is what the service manager starts ("shentu service run
// [--bot]").
func runService(cfg *Config, env *tools.Env, sp svcSpec) error {
	if is, err := svc.IsWindowsService(); err != nil || !is {
		return fmt.Errorf("shentu service run is started by the Windows service manager; use shentu service start%s", sp.flag)
	}
	elog, err := eventlog.Open(sp.name)
	if err != nil {
		return err
	}
	defer elog.Close()
	w := &worker{name: sp.name, log: elog, secret: botToken(cfg)}
	if sp.name == botSpec.name {
		w.run = func(ctx context.Context) error { return botCommand(ctx, cfg, env, nil) }
	} else {
		w.run = func(ctx context.Context) error {
			runSchedule(ctx, time.Minute, patrolEvery, patrolJitter, func(now time.Time) time.Time { return nextDaily(now, dailyHour) },
				func(daily bool) error { return patrol(ctx, cfg, env, daily, false) }, w.logf)
			return nil
		}
	}
	return svc.Run(sp.name, w)
}

// worker runs one service's loop until the service manager stops it or
// the loop ends: with an error the service stops failed (exit code 1) and
// the recovery actions restart it; without one it stays stopped (a paused
// bot, a bot set to notifications only).
type worker struct {
	name   string
	log    *eventlog.Log
	secret string // the bot token: never written to the event log
	run    func(context.Context) error
}

// logf writes a warning to the event log, secrets masked.
func (w *worker) logf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	if w.secret != "" {
		msg = strings.ReplaceAll(msg, w.secret, "[token]")
	}
	w.log.Warning(1, mask(msg))
}

func (w *worker) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	w.log.Info(1, w.name+" started")
	for {
		select {
		case err := <-done:
			if err != nil {
				w.logf("%s stopped: %v", w.name, err)
				return false, 1
			}
			w.log.Info(1, w.name+" finished")
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(20 * time.Second): // work in flight is abandoned
				}
				w.log.Info(1, w.name+" stopped")
				return false, 0
			}
		}
	}
}
