package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

func TestWinAccountsAudit(t *testing.T) {
	oldList, oldKeys := winAccountList, winAdminKeys
	t.Cleanup(func() { winAccountList, winAdminKeys = oldList, oldKeys })
	const base = "S-1-5-21-1-2-3-"
	winAccountList = func() hostenv.Obs[[]hostenv.Account] {
		return hostenv.OK([]hostenv.Account{
			{Name: "Administrator", UID: base + "500", CanLogin: true, IsAdmin: true},
			{Name: "Guest", UID: base + "501", Disabled: true},
			{Name: "alice", UID: base + "1001", CanLogin: true, IsAdmin: true},
			{Name: "svc", UID: base + "1002", CanLogin: true},
			{Name: "old", UID: base + "1003", IsAdmin: true, Disabled: true},
		})
	}
	winAdminKeys = filepath.Join(t.TempDir(), "administrators_authorized_keys")
	os.WriteFile(winAdminKeys, []byte("# admins\nssh-ed25519 AAAA one\n\nssh-ed25519 AAAA two\n"), 0o600)
	a, err := winAccountsAudit()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(a.Administrators, ",") != "Administrator,alice,old (disabled)" ||
		strings.Join(a.LoginAccounts, ",") != "Administrator,alice,svc" || strings.Join(a.Disabled, ",") != "Guest,old" {
		t.Errorf("lists: %+v", a)
	}
	if a.BuiltinAdministrator != "enabled, not renamed" || a.Guest != "disabled" {
		t.Errorf("built-in accounts: %q %q", a.BuiltinAdministrator, a.Guest)
	}
	if a.AdminKeys == nil || a.AdminKeys.Keys != 2 {
		t.Errorf("administrators_authorized_keys: %+v", a.AdminKeys)
	}
	winAccountList = func() hostenv.Obs[[]hostenv.Account] {
		return hostenv.Unknown[[]hostenv.Account](hostenv.ReasonPermission, "denied")
	}
	if _, err := winAccountsAudit(); err == nil {
		t.Error("an unreadable account list must be an error, never an empty audit")
	}
}
