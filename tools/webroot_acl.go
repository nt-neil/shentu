package tools

import (
	"errors"
	"runtime"
	"strings"

	"github.com/nt-neil/shentu/hostenv"
)

// webrootACL checks who may write each web root (Windows only; tests flip it).
var webrootACL = runtime.GOOS == "windows"

// winFileSecurity reads a path's owner and writers; tests replace it.
var winFileSecurity = func(path string) (hostenv.WinFileSecurity, error) {
	ws, ok := winSource().(hostenv.WinSource)
	if !ok {
		return hostenv.WinFileSecurity{}, errors.New("not a Windows source")
	}
	return ws.FileSecurity(path)
}

// webrootFindings reports, once per web root, the accounts other than
// SYSTEM, Administrators and TrustedInstaller that own or may write it:
// a web server's content writable by them can be replaced with a
// webshell. The audit of the files themselves goes on as usual.
func webrootFindings(webRoots []string) []CodeFinding {
	if !webrootACL {
		return nil
	}
	var out []CodeFinding
	for _, r := range webRoots {
		sec, err := winFileSecurity(r)
		if err != nil {
			// Not silence: a report must say what it could not check.
			out = append(out, finding("webroot_acl_unknown", "info", r, 0,
				"cannot tell webroot ACL: "+err.Error(), "run Shentu elevated, as the service does"))
			continue
		}
		if bad := sec.Untrusted(); len(bad) > 0 {
			out = append(out, finding("webroot_writable", "warning", r, 0,
				"webroot writable by non-admin: "+strings.Join(bad, ", "),
				"take write access away from these accounts (IIS needs read only); keep uploads in a folder of their own with script execution off"))
		}
	}
	return out
}

// notChecked lists the findings that say a check could not tell.
func notChecked(fs []CodeFinding) []string {
	var out []string
	for _, f := range fs {
		if f.Kind == "webroot_acl_unknown" {
			out = append(out, f.Path+": "+f.Detail)
		}
	}
	return out
}
