package tools

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"sort"
	"strings"

	"github.com/nt-neil/shentu/hostenv"
)

// winAccountList reads the local accounts; tests replace it.
var winAccountList = func() hostenv.Obs[[]hostenv.Account] {
	return hostenv.WindowsCollector{}.Accounts(winSource())
}

// winAdminKeys is OpenSSH's key file for administrators on Windows.
var winAdminKeys = `C:\ProgramData\ssh\administrators_authorized_keys`

// WinAccounts is accounts_audit on Windows.
type WinAccounts struct {
	Administrators []string `json:"administrators"` // members of Administrators; "(disabled)" marked
	LoginAccounts  []string `json:"login_accounts"` // enabled accounts that can log on
	Disabled       []string `json:"disabled_accounts,omitempty"`
	// BuiltinAdministrator (RID 500) and Guest (RID 501): their state and
	// name; an enabled Administrator that keeps its name is the first
	// account a password spray tries.
	BuiltinAdministrator string   `json:"builtin_administrator,omitempty"`
	Guest                string   `json:"guest,omitempty"`
	AdminKeys            *KeyFile `json:"administrators_authorized_keys,omitempty"`
	Partial              string   `json:"partial,omitempty"`
}

func rid(sid string) string { return sid[strings.LastIndexByte(sid, '-')+1:] }

// winAccountsAudit reports the local accounts. An unreadable account list
// is an error, not an empty audit.
func winAccountsAudit() (WinAccounts, error) {
	o := winAccountList()
	if !o.Known() {
		return WinAccounts{}, errors.New("the Windows accounts could not be read: " + o.Detail)
	}
	var a WinAccounts
	if o.Status == hostenv.StatusPartial {
		a.Partial = o.Detail
	}
	for _, u := range o.Value {
		state := "enabled"
		if u.Disabled {
			state = "disabled"
		}
		if u.IsAdmin {
			n := u.Name
			if u.Disabled {
				n += " (disabled)"
			}
			a.Administrators = append(a.Administrators, n)
		}
		switch {
		case u.Disabled:
			a.Disabled = append(a.Disabled, u.Name)
		case u.CanLogin:
			a.LoginAccounts = append(a.LoginAccounts, u.Name)
		}
		switch rid(u.UID) {
		case "500":
			named := "renamed to " + u.Name
			if strings.EqualFold(u.Name, "Administrator") {
				named = "not renamed"
			}
			a.BuiltinAdministrator = state + ", " + named
		case "501":
			a.Guest = state
		}
	}
	for _, l := range [][]string{a.Administrators, a.LoginAccounts, a.Disabled} {
		sort.Strings(l)
	}
	if st, err := os.Stat(winAdminKeys); err == nil {
		k := KeyFile{User: "Administrators", Path: winAdminKeys, Modified: st.ModTime()}
		if b, err := os.ReadFile(winAdminKeys); err == nil {
			sc := bufio.NewScanner(bytes.NewReader(b))
			for sc.Scan() {
				if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
					k.Keys++
				}
			}
		}
		a.AdminKeys = &k
	}
	return a, nil
}
