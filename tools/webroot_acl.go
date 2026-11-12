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
