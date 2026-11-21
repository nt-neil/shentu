package tools

import (
	"context"
	"strings"

	"github.com/nt-neil/shentu/hostenv"
)

// macAccountList reads the macOS accounts (dscl: no root needed); tests
// replace it.
var macAccountList = func(ctx context.Context) hostenv.Obs[[]hostenv.Account] {
	return hostenv.DarwinCollector{}.Accounts(ctx, hostSource())
}

// macSudoRules reads sudoers (root's only on macOS); tests replace it.
var macSudoRules = func(src hostenv.Source) ([]string, hostenv.Obs[struct{}]) { return linux.SudoRules(src) }

// macNotApplicable are the Linux account checks macOS has no counterpart of.
var macNotApplicable = []string{"ld_so_preload", "pam_modules_not_from_a_package"}

// macAccountsAudit is accounts_audit on macOS (phase 5, M0): accounts from
// dscl, authorized_keys in the login accounts' and uid 0's homes (as the
// darwin collector reads them), sudoers when it can be read. What could
// not be read, and the Linux checks that do not apply (ld.so.preload, PAM
// modules from packages), is said in Note, never left as an empty list
// that looks like a clean host.
func macAccountsAudit(ctx context.Context) Accounts {
	var a Accounts
	var notes []string
	accts := macAccountList(ctx)
	if !accts.Known() {
		a.Note = "the accounts could not be read on macOS (" + string(accts.Reason) + "): " + Cut(accts.Detail, 200)
		a.NotApplicable = macNotApplicable
		return a
	}
	if accts.Status == hostenv.StatusPartial {
		notes = append(notes, "accounts partly read ("+string(accts.Reason)+"): "+Cut(accts.Detail, 200))
	}
	var keyed []hostenv.Account // whose authorized_keys sshd reads: login accounts and uid 0
	for _, acct := range accts.Value {
		if acct.UID == "0" {
			a.UID0 = append(a.UID0, acct.Name)
		}
		if acct.CanLogin {
			a.LoginAccounts = append(a.LoginAccounts, acct.Name)
		}
		if acct.CanLogin || acct.UID == "0" {
			keyed = append(keyed, acct)
		}
	}
	src := hostSource()
	keys := linux.SSHKeyFiles(src, keyed)
	if !keys.Known() {
		notes = append(notes, "authorized_keys could not be read ("+string(keys.Reason)+")")
	} else if keys.Status == hostenv.StatusPartial {
		notes = append(notes, "some authorized_keys could not be read ("+string(keys.Reason)+")")
	}
	a.KeyFiles = keyFilesOf(keys.Value)
	a.SharedKeys = sharedKeys(a.KeyFiles)
	rules, sudo := macSudoRules(src)
	a.SudoRules = rules
	if sudo.Status != hostenv.StatusOK {
		notes = append(notes, "sudoers could not be read ("+string(sudo.Reason)+"; it is root's only)")
	}
	a.Note = strings.Join(notes, "; ")
	a.NotApplicable = macNotApplicable
	return a
}
