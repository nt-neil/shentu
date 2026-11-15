//go:build windows

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"github.com/nt-neil/shentu/hostenv"
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
// OWNER RIGHTS (OW) gets read only, which takes away an owner's implicit
// right to rewrite the DACL: an account later dropped from Administrators
// keeps no hold over files it once created here.
const stateSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;OW)"

// secureDir makes dir a folder that only SYSTEM and Administrators control.
// A missing dir is created with its owner and DACL in one step
// (CreateDirectory with a security descriptor), leaving no moment in
// which a user could slip a file in. An existing dir must already be
// trusted (see checkTrusted): a folder a user created first, with whatever
// they put inside, is refused rather than repaired. Its DACL is then set
// again, in case an administrator loosened it.
func secureDir(dir string, repair bool) error {
	sd, err := windows.SecurityDescriptorFromString("O:BA" + stateSDDL)
	if err != nil {
		return err
	}
	if fi, err := os.Lstat(dir); err == nil {
		if fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
			return fmt.Errorf("refusing %s: it is a link or junction", dir)
		}
		if err := checkTrusted(dir); err != nil {
			return fmt.Errorf("refusing %s: %w; remove it as an administrator and run again", dir, err)
		}
		if !repair {
			return nil // patrol, survey, chat, bot: check only
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			return err
		}
		owner, _, err := sd.Owner()
		if err != nil {
			return err
		}
		return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, dacl, nil)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	if err := windows.CreateDirectory(p, &sa); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err) // includes a folder that appeared meanwhile
	}
	return nil
}

// trustedInstaller is NT SERVICE\TrustedInstaller, owner of system files.
var trustedInstaller, _ = windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")

func trustedSID(s *windows.SID) bool {
	return s != nil && (s.IsWellKnown(windows.WinLocalSystemSid) || s.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
		trustedInstaller != nil && s.Equals(trustedInstaller))
}

// adminMembers are the direct members of the local Administrators group
// (an administrator who saves shentu.toml owns it as themselves).
var adminMembers = sync.OnceValue(func() map[string]bool {
	m := map[string]bool{}
	sids, _ := (&hostenv.Live{}).GroupMembers("S-1-5-32-544")
	for _, s := range sids {
		m[s] = true
	}
	return m
})

// trustedOwner accepts SYSTEM, Administrators and TrustedInstaller; with
// memberOK also an account in the Administrators group, as the owner of
// what an administrator saved inside the folder. Only the top folder,
// which a user could have created first, needs the strict owner: inside
// it only administrators can write, and the inherited OWNER RIGHTS entry
// leaves an owner no implicit right to change the DACL.
func trustedOwner(s *windows.SID, memberOK bool) bool {
	return trustedSID(s) || memberOK && s != nil && adminMembers()[s.String()]
}

// fileDeleteChild is FILE_DELETE_CHILD (winnt.h), missing from x/sys.
const fileDeleteChild = 0x40

// writeRights are the access bits that let a trustee change a file or a
// folder's contents, metadata or security.
const writeRights = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | fileDeleteChild |
	windows.FILE_WRITE_ATTRIBUTES | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL | windows.GENERIC_WRITE

// checkTrusted refuses path when someone other than SYSTEM, Administrators
// or TrustedInstaller owns it or may write it. A missing path is fine.
func checkTrusted(path string) error { return checkTrustedAs(path, false) }

// checkTrustedAs is checkTrusted, accepting an administrator's own
// account as owner when memberOK (see trustedOwner). Write entries are
// always held to SYSTEM, Administrators and TrustedInstaller.
func checkTrustedAs(path string, memberOK bool) error {
	return checkRights(path, memberOK, writeRights, false)
}

// parentRights let a trustee replace or move what a folder holds: delete
// a child or the folder itself, or change its DACL or owner. Creating a
// file or folder (which C:\ grants every user) is not among them.
const parentRights = fileDeleteChild | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL

// checkRights refuses path when its owner, or any allow entry with one of
// rights, is someone other than SYSTEM, Administrators or TrustedInstaller
// (memberOK: the owner may be an administrator's own account;
// writerMemberOK: so may the holders of rights).
func checkRights(path string, memberOK bool, rights windows.ACCESS_MASK, writerMemberOK bool) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || !trustedOwner(owner, memberOK) {
		return fmt.Errorf("%s is owned by %v, not SYSTEM or an administrator", path, owner)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%s has no access list: anyone may change it", path)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue // a deny entry only takes rights away
		default:
			// Object, callback and conditional entries can grant rights in
			// ways this check does not read: not trusted.
			return fmt.Errorf("%s has an access entry of type %d that Shentu does not evaluate", path, ace.Header.AceType)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Mask&rights != 0 && !trustedOwner(sid, writerMemberOK) {
			return fmt.Errorf("%s may be changed by %s", path, sid)
		}
	}
	return nil
}

// trustConfig decides whether the configuration folder may be read. On
// Windows users may create folders under %ProgramData%, so a folder made
// before installation, with a shentu.toml, env file or skills in it, must
// not be loaded by the service running as SYSTEM. Every entry of the
// folder is checked (see trustedTree). A missing folder is created right
// away with the trusted ACL, so nobody can plant one between this check
// and a later read. Only when that fails for lack of privilege (not
// elevated) are the defaults used, with nothing read; any other failure,
// such as a folder that appeared meanwhile, is a refusal.
func trustConfig(path string) (load bool, err error) {
	dir := filepath.Dir(path)
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		if err := secureDir(dir, false); err != nil {
			if errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) ||
				errors.Is(err, windows.ERROR_INVALID_OWNER) {
				return false, nil
			}
			return false, fmt.Errorf("refusing the configuration: %w", err)
		}
	}
	if err := trustedTree(dir); err != nil {
		return false, fmt.Errorf("refusing the configuration: %w; remove the folder or reset its owner and permissions as an administrator", err)
	}
	return true, nil
}

// trustedTree checks dir and everything in it with checkTrusted and
// refuses links and junctions anywhere.
func trustedTree(dir string) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
			return fmt.Errorf("%s is a link or junction", p)
		}
		return checkTrustedAs(p, p != dir)
	})
}

// trustSkills is checked where skills are read: the configuration folder
// holding them must be trusted then (it also decides whether a missing
// skills folder could still be planted).
func trustSkills(dir string) bool { return trustedTree(filepath.Dir(dir)) == nil }

// ensureStateDir secures %ProgramData%\Shentu (config, env file with
// tokens, state) and the state directory, wherever it is configured.
// Setting the ACL needs an elevated process, as the service runs.
func ensureStateDir(dir string) error {
	if err := secureDir(filepath.Join(programData(), "Shentu"), false); err != nil {
		return err
	}
	if err := trustedParents(dir); err != nil {
		return err
	}
	return secureDir(dir, false)
}

// trustedParents checks the folders above a state directory configured
// outside %ProgramData%\Shentu: whoever may delete, move or re-permission
// one of them could swap the state directory for their own. The path must
// be absolute on a drive (no UNC, no drive-relative form); every existing
// folder above it must be a plain folder (no link or junction) that only
// administrators may change; a missing one is created here, with the
// protected descriptor, never with inherited permissions.
func trustedParents(dir string) error {
	root := filepath.Join(programData(), "Shentu")
	if rel, err := filepath.Rel(root, dir); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) &&
		filepath.IsAbs(dir) {
		return nil // under %ProgramData%\Shentu, secured above
	}
	vol := filepath.VolumeName(dir)
	if !filepath.IsAbs(dir) || len(vol) != 2 || vol[1] != ':' {
		return fmt.Errorf("refusing state directory %q: it must be an absolute path on a drive, such as D:\\Shentu\\state", dir)
	}
	var parents []string // from the drive root down
	for p := filepath.Dir(filepath.Clean(dir)); ; p = filepath.Dir(p) {
		parents = append([]string{p}, parents...)
		if filepath.Dir(p) == p {
			break
		}
	}
	for _, p := range parents {
		fi, err := os.Lstat(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := secureDir(p, false); err != nil { // created with stateSDDL in one step
				return fmt.Errorf("refusing state directory %s: %w", dir, err)
			}
			continue
		case err != nil:
			return fmt.Errorf("refusing state directory %s: %w", dir, err)
		case fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 && filepath.Dir(p) != p:
			return fmt.Errorf("refusing state directory %s: %s is a link or junction", dir, p)
		}
		if err := checkRights(p, true, parentRights, true); err != nil {
			return fmt.Errorf("refusing state directory %s: a folder above it is not safe: %w", dir, err)
		}
	}
	return nil
}

// installStateDir is ensureStateDir for service install, the one place
// that also sets the owner and the DACL again on folders that exist (an
// administrator may have loosened them). Every other run only checks.
func installStateDir(dir string) error {
	if err := secureDir(filepath.Join(programData(), "Shentu"), true); err != nil {
		return err
	}
	if err := trustedParents(dir); err != nil {
		return err
	}
	return secureDir(dir, true)
}

// privileged reports an elevated process (the service runs as LocalSystem).
func privileged() bool { return windows.GetCurrentProcessToken().IsElevated() }

// privilegeError is what a command that changes the state says without it.
func privilegeError(what string) error {
	return errors.New(what + ` changes %ProgramData%\Shentu; run it from an elevated prompt (Run as administrator)`)
}

// unprivilegedNote is chat's warning without it.
const unprivilegedNote = "note: not elevated; the Security log, scheduled tasks and some process details will be unreadable."

// How the bot is (re)started on Windows: shentu bot in an elevated prompt.
const (
	botRestartHint = "Start the bot again: shentu bot (in an elevated prompt)"
	botRunningHint = "The bot must be running (shentu bot in another elevated prompt)"
)

// stateReady is checked before chat and bot: the state directory must be
// Shentu's own, made by an elevated run (service install), never created
// here by whoever runs the command.
func stateReady(dir string) error {
	if err := ensureStateDir(dir); err != nil {
		return fmt.Errorf("%w; run shentu service install from an elevated prompt first, or run this elevated", err)
	}
	return nil
}
