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

// The Windows service runs the patrol schedule (schedule.go) as
// LocalSystem, which reading the Security log and the task store needs.
// It only reads: the Windows MVP takes no action on the host.
const (
	serviceName    = "Shentu"
	serviceDisplay = "Shentu security patrol"
	serviceDesc    = "Read-only security patrol: Windows facts, checks, MSRC/KEV, IIS code audit; reports by the configured notifier."
)

const serviceUsage = "usage: shentu service install|uninstall|start|stop|status"

func serviceCommand(ctx context.Context, cfg *Config, env *tools.Env, args []string) error {
	if len(args) != 1 {
		return errors.New(serviceUsage)
	}
	switch args[0] {
	case "install":
		return installService(cfg)
	case "uninstall":
		return uninstallService()
	case "start":
		return withService(func(s *mgr.Service) error { return s.Start() })
	case "stop":
		return withService(func(s *mgr.Service) error { return stopService(s) })
	case "status":
		return withService(func(s *mgr.Service) error {
			st, err := s.Query()
			if err == nil {
				fmt.Println(stateName(st.State))
			}
			return err
		})
	case "run":
		return runService(cfg, env)
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
func installService(cfg *Config) error {
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
		return fmt.Errorf("install from %s: copy shentu.exe there (as an administrator) and run %s service install",
			want, filepath.Join(want, "shentu.exe"))
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
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return errors.New("the Shentu service is already installed; uninstall it first to reinstall")
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName: serviceDisplay, Description: serviceDesc,
		StartType: mgr.StartAutomatic, DelayedAutoStart: true, // LocalSystem: no ServiceStartName
	}, "service", "run")
	if err != nil {
		return err
	}
	defer s.Close()
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: time.Minute}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, uint32((24 * time.Hour).Seconds())); err != nil {
		s.Delete()
		return err
	}
	if err := eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) &&
		!alreadyRegistered(err) {
		s.Delete()
		return err
	}
	fmt.Println("installed the Shentu service (automatic, LocalSystem); start it with: shentu service start")
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
	empty, err := windows.ACLFromEntries(nil, nil)
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

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("the Shentu service is not installed: %w", err)
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
	eventlog.Remove(serviceName)
	fmt.Println("removed the Shentu service; configuration and state in", filepath.Dir(defaultConfigPath()), "are kept")
	return nil
}

func withService(f func(*mgr.Service) error) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("the Shentu service is not installed: %w", err)
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
			return errors.New("the Shentu service did not stop within 30 s")
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

// runService is what the service manager starts ("shentu service run").
func runService(cfg *Config, env *tools.Env) error {
	if is, err := svc.IsWindowsService(); err != nil || !is {
		return errors.New("shentu service run is started by the Windows service manager; use shentu service start")
	}
	elog, err := eventlog.Open(serviceName)
	if err != nil {
		return err
	}
	defer elog.Close()
	return svc.Run(serviceName, &patrolService{cfg: cfg, env: env, log: elog})
}

type patrolService struct {
	cfg *Config
	env *tools.Env
	log *eventlog.Log
}

func (p *patrolService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runSchedule(ctx, time.Minute, patrolEvery, patrolJitter, func(now time.Time) time.Time { return nextDaily(now, dailyHour) },
			func(daily bool) error { return patrol(ctx, p.cfg, p.env, daily, false) },
			func(format string, a ...any) { p.log.Warning(1, fmt.Sprintf(format, a...)) })
	}()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	p.log.Info(1, "Shentu patrol started")
	for c := range req {
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			cancel()
			select {
			case <-done:
			case <-time.After(20 * time.Second): // a patrol in flight is abandoned
			}
			p.log.Info(1, "Shentu patrol stopped")
			return false, 0
		}
	}
	cancel()
	return false, 0
}
