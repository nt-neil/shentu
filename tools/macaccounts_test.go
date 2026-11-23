package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// M0: on macOS (the synthetic fixture) accounts come from dscl: root is
// uid 0, root and user1 can log in; root's authorized_keys could not be
// read (not root), which the note says (its sudoers is readable);
// the Linux-only checks are not applicable, not "none found".
func TestMacAccountsAudit(t *testing.T) {
	rp, err := hostenv.LoadReplay("../hostenv/testdata/darwin/macos27-synthetic-user")
	if err != nil {
		t.Fatal(err)
	}
	withHost(t, rp)
	a := AccountsAudit()
	if !slices.Equal(a.UID0, []string{"root"}) || !slices.Contains(a.LoginAccounts, "user1") || !slices.Contains(a.LoginAccounts, "root") || slices.Contains(a.LoginAccounts, "_www") {
		t.Errorf("accounts: uid0 %v, login %v", a.UID0, a.LoginAccounts)
	}
	if !strings.Contains(a.Note, "authorized_keys") || strings.Contains(a.Note, "sudoers") { // the fixture's sudoers is readable
		t.Errorf("note: %q", a.Note)
	}
	if !slices.Equal(a.NotApplicable, []string{"ld_so_preload", "pam_modules_not_from_a_package"}) || a.Preload != nil || a.UnpackagedPAM != nil {
		t.Errorf("not applicable %v, preload %v, pam %v", a.NotApplicable, a.Preload, a.UnpackagedPAM)
	}
	tool, _ := Find("accounts_audit")
	out, err := tool.Run(context.Background(), &Env{}, json.RawMessage(`{}`))
	if acc, ok := out.(Accounts); err != nil || !ok || len(acc.LoginAccounts) == 0 {
		t.Errorf("tool: %T %v %v", out, out, err)
	}
}

// M0: an unreadable macOS host says so; no account list that looks clean.
func TestMacAccountsUnknown(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"format":"`+hostenv.FixtureFormat+`","info":{"goos":"darwin","goarch":"arm64"},"entries":[]}`), 0o600)
	os.Mkdir(filepath.Join(dir, "blobs"), 0o700)
	rp, err := hostenv.LoadReplay(dir)
	if err != nil {
		t.Fatal(err)
	}
	withHost(t, rp)
	a := AccountsAudit()
	if !strings.Contains(a.Note, "could not be read on macOS") || len(a.UID0)+len(a.LoginAccounts) != 0 {
		t.Errorf("unreadable: %+v", a)
	}
}

// M0: a partial account list is said.
func TestMacAccountsPartial(t *testing.T) {
	rp, _ := hostenv.LoadReplay("../hostenv/testdata/darwin/macos27-synthetic-user")
	withHost(t, rp)
	old := macAccountList
	macAccountList = func(context.Context) hostenv.Obs[[]hostenv.Account] {
		return hostenv.Partial([]hostenv.Account{{Name: "user1", UID: "501", CanLogin: true, Home: "/Users/user1"}}, hostenv.ReasonCommandFailed, "shells unknown")
	}
	t.Cleanup(func() { macAccountList = old })
	if a := AccountsAudit(); !strings.Contains(a.Note, "accounts partly read") {
		t.Errorf("partial: %q", a.Note)
	}
}

// M0: sudoers that cannot be read (not root, as on most Macs) is said.
func TestMacAccountsSudoersUnread(t *testing.T) {
	rp, _ := hostenv.LoadReplay("../hostenv/testdata/darwin/macos27-synthetic-user")
	withHost(t, rp)
	old := macSudoRules
	macSudoRules = func(hostenv.Source) ([]string, hostenv.Obs[struct{}]) {
		return nil, hostenv.Unknown[struct{}](hostenv.ReasonPermission, "/etc/sudoers: permission denied")
	}
	t.Cleanup(func() { macSudoRules = old })
	if a := AccountsAudit(); !strings.Contains(a.Note, "sudoers could not be read") {
		t.Errorf("note: %q", a.Note)
	}
}

// N-180-1: accounts that cannot be read are named (NotRead), and the survey
// says so in a risk the patrol lists as not checked, never an empty,
// clean-looking login account list.
func TestMacSurveyAccountsUnreadable(t *testing.T) {
	rp, _ := hostenv.LoadReplay("../hostenv/testdata/darwin/macos27-synthetic-user")
	withHost(t, rp)
	old := macAccountList
	macAccountList = func(context.Context) hostenv.Obs[[]hostenv.Account] {
		return hostenv.Unknown[[]hostenv.Account](hostenv.ReasonCommandFailed, "dscl failed")
	}
	t.Cleanup(func() { macAccountList = old })
	if a := AccountsAudit(); !slices.Equal(a.NotRead, []string{"accounts", "authorized_keys", "sudoers"}) {
		t.Errorf("not read: %v", a.NotRead)
	}
	p := Survey(context.Background(), &Env{})
	found := false
	for _, r := range p.Risks {
		found = found || r.Key == "accounts:unreadable" && Unchecked(r)
	}
	if !found || len(p.LoginAccounts) != 0 {
		t.Errorf("risks %v, login accounts %v", p.Risks, p.LoginAccounts)
	}
}
