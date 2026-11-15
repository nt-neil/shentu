package tools

import (
	"errors"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// The code-audit tests use temp folders as web roots, which their own user
// may write: the web-root check stays off in tests unless one turns it on.
func init() { webrootACL = false }

// S2b: one warning per web root that someone besides SYSTEM,
// Administrators or TrustedInstaller may write, naming them.
func TestWebrootFindings(t *testing.T) {
	oldOn, oldSec := webrootACL, winFileSecurity
	t.Cleanup(func() { webrootACL, winFileSecurity = oldOn, oldSec })
	webrootACL = true
	winFileSecurity = func(p string) (hostenv.WinFileSecurity, error) {
		if strings.HasSuffix(p, "shop") {
			return hostenv.WinFileSecurity{Owner: "S-1-5-32-544", Writers: []string{"S-1-5-18", "S-1-5-32-545", "S-1-5-17"}}, nil
		}
		return hostenv.WinFileSecurity{Owner: "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", Writers: []string{"S-1-5-18"}}, nil
	}
	got := webrootFindings([]string{`C:\inetpub\wwwroot`, `D:\sites\shop`})
	if len(got) != 1 || got[0].Kind != "webroot_writable" || got[0].Severity != "warning" || got[0].Path != `D:\sites\shop` ||
		!strings.Contains(got[0].Detail, "S-1-5-32-545, S-1-5-17") {
		t.Errorf("findings: %+v", got)
	}
	// Unreadable: an info finding, listed as not checked, never silence.
	winFileSecurity = func(string) (hostenv.WinFileSecurity, error) {
		return hostenv.WinFileSecurity{}, errors.New("access denied")
	}
	got = webrootFindings([]string{`E:\site`})
	if len(got) != 1 || got[0].Kind != "webroot_acl_unknown" || got[0].Severity != "info" ||
		!strings.Contains(got[0].Detail, "cannot tell webroot ACL") || len(notChecked(got)) != 1 {
		t.Errorf("unreadable ACL: %+v", got)
	}
	webrootACL = false
	if got := webrootFindings([]string{`D:\sites\shop`}); got != nil {
		t.Errorf("off outside Windows: %+v", got)
	}
}
