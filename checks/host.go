package checks

import (
	"fmt"
	"strings"

	"github.com/nt-neil/shentu/hostenv"
)

// The first checks, written against facts only. They mirror behaviour that
// lives in tools/ today; Phase 1c points tools/ at these and deletes the
// copies once v0.2.5 is on main.

func init() {
	register(checkFunc{"ssh", sshSettings})
	register(checkFunc{"persistence.ld_preload", ldPreload})
	register(checkFunc{"process.exe_deleted_or_temp", exeDeletedOrTemp})
	register(checkFunc{"rdp.no_nla", rdpNoNLA})
}

// sshSettings mirrors tools/survey.go sshRisks: one finding per setting,
// and one cannot_tell when the settings could not be read.
func sshSettings(f *hostenv.Facts) []Finding {
	o := f.RemoteAccess.SSH
	if out := cannotTell("ssh.settings", "SSH settings could not be read", o); out != nil {
		return out
	}
	if !o.Known() {
		return nil
	}
	s := o.Value.Settings
	var out []Finding
	if s["passwordauthentication"] == "yes" {
		out = append(out, Finding{Check: "ssh.password_auth", Status: StatusFail, Severity: SevMedium,
			Title:    "SSH accepts passwords; key-only login stops brute force",
			Evidence: o.Value.ConfigPath + ": PasswordAuthentication yes"})
	}
	if s["permitrootlogin"] == "yes" {
		out = append(out, Finding{Check: "ssh.root_login", Status: StatusFail, Severity: SevMedium,
			Title:    "SSH allows root to log in with a password",
			Evidence: o.Value.ConfigPath + ": PermitRootLogin yes"})
	}
	if s["passwordauthentication"] == "unknown" || s["permitrootlogin"] == "unknown" {
		// Say the reason it has: only a permission problem is solved by root.
		reason := o.Reason
		if reason == "" {
			reason = hostenv.ReasonPermission
		}
		title := "SSH settings could not be read (" + string(reason) + ")"
		if reason == hostenv.ReasonPermission {
			title = "SSH settings could not be read; run Shentu as root"
		}
		out = append(out, Finding{Check: "ssh.settings", Status: StatusCannotTell, Severity: SevInfo,
			Title: title, Reason: string(reason), Evidence: strings.Join(o.Value.Unread, ", ")})
	}
	return out
}

func ldPreload(f *hostenv.Facts) []Finding {
	o := f.Persistence
	if out := cannotTell("persistence.ld_preload", "Persistence locations could not be read", o); out != nil {
		return out
	}
	var out []Finding
	for _, it := range o.Value {
		if it.Kind == "ld_preload" {
			out = append(out, Finding{Check: "persistence.ld_preload", Status: StatusFail, Severity: SevHigh,
				Title: "A library is preloaded into every program", Evidence: it.Location + ": " + it.Command})
		}
	}
	return out
}

func exeDeletedOrTemp(f *hostenv.Facts) []Finding {
	o := f.Processes
	if out := cannotTell("process.exe_deleted_or_temp", "Processes could not be listed", o); out != nil {
		return out
	}
	var out []Finding
	for _, p := range o.Value {
		switch {
		case p.ExeKnown && !p.ExeExists:
			out = append(out, Finding{Check: "process.exe_deleted_or_temp", Status: StatusFail, Severity: SevHigh,
				Title: "A process runs from a deleted executable", Evidence: fmt.Sprintf("pid %d %s (%s)", p.PID, p.Name, p.Exe)})
		case p.InTemp:
			out = append(out, Finding{Check: "process.exe_deleted_or_temp", Status: StatusFail, Severity: SevHigh,
				Title: "A process runs from a temporary directory", Evidence: fmt.Sprintf("pid %d %s (%s)", p.PID, p.Name, p.Exe)})
		}
	}
	if o.Status == hostenv.StatusPartial {
		out = append(out, Finding{Check: "process.exe_deleted_or_temp", Status: StatusCannotTell, Severity: SevInfo,
			Title: "Some processes could not be inspected", Reason: string(o.Reason), Evidence: o.Detail})
	}
	return out
}

func rdpNoNLA(f *hostenv.Facts) []Finding {
	o := f.RemoteAccess.RDP
	if out := cannotTell("rdp.no_nla", "RDP settings could not be read", o); out != nil {
		return out
	}
	if o.Known() && o.Value.Enabled && !o.Value.NLA {
		return []Finding{{Check: "rdp.no_nla", Status: StatusFail, Severity: SevHigh,
			Title:    "Remote Desktop accepts connections without Network Level Authentication",
			Evidence: fmt.Sprintf("port %d, security layer %s", o.Value.Port, o.Value.SecurityLayer)}}
	}
	return nil
}
