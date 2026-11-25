package tools

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
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
	src := winSource() // the key file of the host read, not of the machine running the check
	// A key file not read in full is said: its count is a floor, never "no keys".
	unread := func(why string) {
		a.Partial = strings.TrimPrefix(a.Partial+"; "+winAdminKeys+" "+why, "; ")
	}
	st, err := hostenv.Stat(src, winAdminKeys)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		unread("could not be checked (" + err.Error() + "): administrators' keys unknown")
	default:
		k := KeyFile{User: "Administrators", Path: winAdminKeys, Modified: st.ModTime}
		b, err := src.ReadFile(winAdminKeys)
		switch {
		case errors.Is(err, hostenv.ErrTruncated):
			unread(fmt.Sprintf("read in part (over %d MiB): keys past it not counted", hostenv.MaxFileBytes>>20))
		case err != nil:
			unread("could not be read (" + err.Error() + "): its keys not counted")
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Buffer(nil, len(b)+1)
		for sc.Scan() {
			if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
				k.Keys++
			}
		}
		a.AdminKeys = &k
	}
	return a, nil
}
