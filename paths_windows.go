//go:build windows

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
const stateSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// secureDir makes dir a folder that only SYSTEM and Administrators control.
// A missing dir is created with its owner and DACL in one step
// (CreateDirectory with a security descriptor), leaving no moment in
// which a user could slip a file in. An existing dir must already be
// trusted (see checkTrusted): a folder a user created first, with whatever
// they put inside, is refused rather than repaired. Its DACL is then set
// again, in case an administrator loosened it.
func secureDir(dir string) error {
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
		dacl, _, err := sd.DACL()
		if err != nil {
			return err
		}
		return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
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

// trustedOwner accepts SYSTEM, Administrators, TrustedInstaller and the
// accounts in the Administrators group.
func trustedOwner(s *windows.SID) bool {
	return trustedSID(s) || s != nil && adminMembers()[s.String()]
}

// fileDeleteChild is FILE_DELETE_CHILD (winnt.h), missing from x/sys.
const fileDeleteChild = 0x40

// writeRights are the access bits that let a trustee change a file or a
// folder's contents, metadata or security.
const writeRights = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | fileDeleteChild |
	windows.FILE_WRITE_ATTRIBUTES | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL | windows.GENERIC_WRITE

// checkTrusted refuses path when someone other than SYSTEM, Administrators
// or TrustedInstaller owns it or may write it. A missing path is fine.
func checkTrusted(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || !trustedOwner(owner) {
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
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Mask&writeRights != 0 && !trustedSID(sid) {
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
		if err := secureDir(dir); err != nil {
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
		return checkTrusted(p)
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
	if err := secureDir(filepath.Join(programData(), "Shentu")); err != nil {
		return err
	}
	return secureDir(dir)
}
