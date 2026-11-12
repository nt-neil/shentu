package hostenv

// Recording and replay of WinSource reads. Each answer is stored as JSON in
// a blob of the usual hostenv-fixture/1 layout, under its own op:
//
//	reg      Path = key      map[string]RegValue
//	subkeys  Path = key      []string
//	winsvc   Path = ""       []WinService
//	winproc  Path = ""       []WinProcess
//	winsock  Path = ""       []WinSocket
//	winuser  Path = ""       []WinUser
//	wingroup Path = SID      []string
//	wintask  Path = ""       []WinTask
//	winevt   Path = channel|max|xpath   []WinEvent
//	wmi      Path = namespace|query|props []map[string]any
//
// The data is masked like everything else at Save time.

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// errNoWinSource is what a Recorder answers when its inner Source cannot
// read Windows APIs (recording a Linux host).
var errNoWinSource = errors.New("hostenv: source cannot read Windows APIs")

func (r *Recorder) win() (WinSource, error) {
	ws, ok := r.Inner.(WinSource)
	if !ok {
		return nil, errNoWinSource
	}
	return ws, nil
}

// putJSON records v (or err) under op/path.
func (r *Recorder) putJSON(op, path string, v any, err error) {
	e := &entry{Op: op, Path: path, Err: errCode(err)}
	if b, jerr := json.Marshal(v); jerr == nil && string(b) != "null" {
		e.data = b
	}
	r.put(e)
}

func recordWin[T any](r *Recorder, op, path string, call func(WinSource) (T, error)) (T, error) {
	var zero T
	ws, err := r.win()
	if err != nil {
		return zero, err
	}
	v, err := call(ws)
	r.putJSON(op, path, v, err)
	return v, err
}

func (r *Recorder) RegValues(key string) (map[string]RegValue, error) {
	return recordWin(r, "reg", key, func(ws WinSource) (map[string]RegValue, error) {
		v, err := ws.RegValues(key)
		return RedactRegValues(v), err
	})
}

func (r *Recorder) RegSubkeys(key string) ([]string, error) {
	return recordWin(r, "subkeys", key, func(ws WinSource) ([]string, error) { return ws.RegSubkeys(key) })
}

func (r *Recorder) Services() ([]WinService, error) {
	return recordWin(r, "winsvc", "", WinSource.Services)
}

func (r *Recorder) Processes() ([]WinProcess, error) {
	return recordWin(r, "winproc", "", WinSource.Processes)
}

func (r *Recorder) Sockets() ([]WinSocket, error) {
	return recordWin(r, "winsock", "", WinSource.Sockets)
}

func (r *Recorder) Users() ([]WinUser, error) {
	return recordWin(r, "winuser", "", WinSource.Users)
}

func (r *Recorder) GroupMembers(sid string) ([]string, error) {
	return recordWin(r, "wingroup", sid, func(ws WinSource) ([]string, error) { return ws.GroupMembers(sid) })
}

func (r *Recorder) Tasks() ([]WinTask, error) {
	return recordWin(r, "wintask", "", WinSource.Tasks)
}

func eventKey(channel, xpath string, max int) string {
	return channel + "|" + strconv.Itoa(max) + "|" + xpath
}

func (r *Recorder) Events(channel, xpath string, max int) ([]WinEvent, error) {
	return recordWin(r, "winevt", eventKey(channel, xpath, max), func(ws WinSource) ([]WinEvent, error) {
		return ws.Events(channel, xpath, max)
	})
}

func replayWin[T any](rp *Replay, op, path string) (T, error) {
	var v T
	e, err := rp.find(op, path, nil)
	if err != nil {
		return v, err
	}
	if e.data != nil {
		if err := json.Unmarshal(e.data, &v); err != nil {
			return v, fmt.Errorf("hostenv: fixture %s %s: %w", op, path, err)
		}
	}
	return v, codeErr(e.Err, path)
}

func (rp *Replay) RegValues(key string) (map[string]RegValue, error) {
	return replayWin[map[string]RegValue](rp, "reg", key)
}
func (rp *Replay) RegSubkeys(key string) ([]string, error) {
	return replayWin[[]string](rp, "subkeys", key)
}
func (rp *Replay) Services() ([]WinService, error) { return replayWin[[]WinService](rp, "winsvc", "") }
func (rp *Replay) Processes() ([]WinProcess, error) {
	return replayWin[[]WinProcess](rp, "winproc", "")
}
func (rp *Replay) Sockets() ([]WinSocket, error) { return replayWin[[]WinSocket](rp, "winsock", "") }
func (rp *Replay) Users() ([]WinUser, error)     { return replayWin[[]WinUser](rp, "winuser", "") }
func (rp *Replay) GroupMembers(sid string) ([]string, error) {
	return replayWin[[]string](rp, "wingroup", sid)
}
func (rp *Replay) Tasks() ([]WinTask, error) { return replayWin[[]WinTask](rp, "wintask", "") }
func (rp *Replay) Events(channel, xpath string, max int) ([]WinEvent, error) {
	return replayWin[[]WinEvent](rp, "winevt", eventKey(channel, xpath, max))
}

// ---- masking hooks used by Masker (identity.go) ----

// winSkipIP reports a Windows fixture entry whose dotted numbers are
// versions, not addresses: the CurrentVersion key itself, and the
// Uninstall and CBS package lists and their direct subkeys. Nothing else
// under CurrentVersion (Winlogon, ProfileList, IFEO) is exempt. Since IPs
// stay unmasked there, winMaskPrep trims those values to the fields the
// collector reads (winIPExemptFields), so free text such as
// UninstallString, InstallLocation or RegisteredOwner is not recorded.
func winSkipIP(e *entry) bool {
	if e.Op != "reg" && e.Op != "subkeys" {
		return false
	}
	if e.Path == KeyCurrentVersion {
		return e.Op == "reg"
	}
	for _, k := range []string{KeyUninstall, KeyUninstall32, KeyCBSPackages} {
		if e.Path == k || (strings.HasPrefix(e.Path, k+`\`) && !strings.Contains(e.Path[len(k)+1:], `\`)) {
			return true
		}
	}
	const userUninstall = `\Software\Microsoft\Windows\CurrentVersion\Uninstall`
	if strings.HasPrefix(e.Path, `HKU\S-1-5-21-`) {
		rest := e.Path[strings.Index(e.Path[4:], `\`)+4:] // after HKU\<SID>
		if rest == userUninstall || (strings.HasPrefix(rest, userUninstall+`\`) && !strings.Contains(rest[len(userUninstall)+1:], `\`)) {
			return true
		}
	}
	return false
}

// winIPExemptFields lists the values kept from a reg entry that
// winSkipIP exempts from IP masking: exactly what the collector reads.
func winIPExemptFields(path string) []string {
	switch {
	case path == KeyCurrentVersion:
		return []string{"ProductName", "DisplayVersion", "ReleaseId", "CurrentBuild", "UBR", "InstallationType"}
	case strings.HasPrefix(path, KeyCBSPackages):
		return []string{"CurrentState", "InstallTimeHigh", "InstallTimeLow"}
	}
	return []string{"DisplayName", "DisplayVersion", "ParentKeyName"} // Uninstall, x64, x86 and per user
}

// shortNames returns the 8.3 aliases Windows may give a profile folder
// named n (C:\Users\RUNNER~1 for runneradmin): the first six usable
// characters in upper case plus ~1 to ~4. Names that already fit 8.3
// have none.
func shortNames(n string) []string {
	var b strings.Builder
	for _, r := range strings.ToUpper(n) {
		if r > ' ' && r < 0x7f && !strings.ContainsRune(`."*/:<>?\|+,;=[]`, r) {
			b.WriteRune(r)
		}
	}
	base := b.String()
	if len(n) <= 8 && base == strings.ToUpper(n) {
		return nil
	}
	base = base[:min(len(base), 6)]
	if base == "" {
		return nil
	}
	out := make([]string, 0, 4)
	for i := 1; i <= 4; i++ {
		out = append(out, fmt.Sprintf("%s~%d", base, i))
	}
	return out
}

// machineSIDRe matches the machine or domain part of an account SID. It
// identifies the host, so fixtures keep only the RID.
var machineSIDRe = regexp.MustCompile(`\bS-1-5-21-\d+-\d+-\d+\b`)

func maskMachineSIDs(s string) string {
	return machineSIDRe.ReplaceAllString(s, "S-1-5-21-1000000000-1000000000-1000000000")
}

// winMaskPrep runs before the masker builds its replacements. It returns
// the names of people found in a Windows recording, to be masked like
// Linux uid 1000+ accounts: local accounts with RID 1000 and up, profile
// folder names, the auto-logon user, and owners of processes and tasks
// running under such a SID, and the domain part of those owners (for a
// local account, the NetBIOS computer name). Each name is also returned
// in upper and lower case: Windows names are case-insensitive, and the
// masker matches exactly. It trims IP-exempt registry entries to the
// fields the collector reads, and blanks the user-name fields of
// recorded events, which hold names typed by whoever tried to log in.
func winMaskPrep(entries []*entry) (out []string) {
	defer func() {
		for _, n := range out[:len(out):len(out)] {
			out = append(out, strings.ToUpper(n), strings.ToLower(n))
			out = append(out, shortNames(n)...)
		}
	}()
	human := func(sid string) bool {
		i := strings.LastIndexByte(sid, '-')
		rid, err := strconv.Atoi(sid[i+1:])
		return strings.HasPrefix(sid, "S-1-5-21-") && i >= 0 && err == nil && rid >= 1000
	}
	afterSlash := func(s string) string { return s[strings.LastIndexByte(s, '\\')+1:] }
	for _, e := range entries {
		if e.data == nil {
			continue
		}
		switch {
		case e.Op == "winuser":
			var users []WinUser
			if json.Unmarshal(e.data, &users) == nil {
				for _, u := range users {
					if human(u.SID) {
						out = append(out, u.Name)
					}
				}
			}
		case e.Op == "winproc":
			var procs []WinProcess
			if json.Unmarshal(e.data, &procs) == nil {
				for _, p := range procs {
					if human(p.SID) && p.User != "" {
						out = append(out, afterSlash(p.User))
						if i := strings.LastIndexByte(p.User, '\\'); i > 0 {
							out = append(out, p.User[:i])
						}
					}
				}
			}
		case e.Op == "reg" && winSkipIP(e):
			var v map[string]RegValue
			if json.Unmarshal(e.data, &v) == nil {
				kept := map[string]RegValue{}
				for _, n := range winIPExemptFields(e.Path) {
					if r, ok := v[n]; ok {
						kept[n] = r
					}
				}
				if b, err := json.Marshal(kept); err == nil {
					e.data = b
				}
			}
		case e.Op == "reg" && strings.HasPrefix(e.Path, KeyProfileList+`\S-1-5-21-`):
			var v map[string]RegValue
			if json.Unmarshal(e.data, &v) == nil {
				if p := v["ProfileImagePath"].String; p != "" {
					out = append(out, afterSlash(p))
				}
			}
		case e.Op == "reg" && e.Path == KeyWinlogon:
			var v map[string]RegValue
			if json.Unmarshal(e.data, &v) == nil {
				for _, n := range []string{"DefaultUserName", "AltDefaultUserName", "LastUsedUsername"} {
					if u := v[n].String; u != "" {
						out = append(out, afterSlash(u))
					}
				}
			}
		case e.Op == "winevt":
			var evs []WinEvent
			if json.Unmarshal(e.data, &evs) == nil {
				for _, ev := range evs {
					for k := range ev.Data {
						if strings.HasSuffix(k, "UserName") || strings.HasSuffix(k, "DomainName") || k == "WorkstationName" {
							ev.Data[k] = "user"
						}
					}
				}
				if b, err := json.Marshal(evs); err == nil {
					e.data = b
				}
			}
		}
	}
	return out
}

func wmiKey(namespace, query string, props []string) string {
	return namespace + "|" + query + "|" + strings.Join(props, ",")
}

func (r *Recorder) WMI(namespace, query string, props []string) ([]map[string]any, error) {
	return recordWin(r, "wmi", wmiKey(namespace, query, props), func(ws WinSource) ([]map[string]any, error) {
		return ws.WMI(namespace, query, props)
	})
}

func (rp *Replay) WMI(namespace, query string, props []string) ([]map[string]any, error) {
	return replayWin[[]map[string]any](rp, "wmi", wmiKey(namespace, query, props))
}
