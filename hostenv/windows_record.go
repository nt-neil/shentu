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
	return recordWin(r, "reg", key, func(ws WinSource) (map[string]RegValue, error) { return ws.RegValues(key) })
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

// winVersionKeys hold version numbers that look like IPv4 addresses.
var winVersionKeys = []string{KeyUninstall, KeyUninstall32, KeyCBSPackages, KeyCurrentVersion, `\Software\Microsoft\Windows\CurrentVersion\Uninstall`}

// winSkipIP reports a Windows fixture entry whose dotted numbers are
// versions, not addresses.
func winSkipIP(e *entry) bool {
	if e.Op != "reg" && e.Op != "subkeys" {
		return false
	}
	for _, k := range winVersionKeys {
		if strings.HasPrefix(e.Path, k) || strings.Contains(e.Path, k) {
			return true
		}
	}
	return false
}

// machineSIDRe matches the machine or domain part of an account SID. It
// identifies the host, so fixtures keep only the RID.
var machineSIDRe = regexp.MustCompile(`\bS-1-5-21-\d+-\d+-\d+\b`)

func maskMachineSIDs(s string) string {
	return machineSIDRe.ReplaceAllString(s, "S-1-5-21-1000000000-1000000000-1000000000")
}

// winHumanUsers lists the local accounts a person created (RID 1000 and
// up) from a recorded NetUserEnum, so their names are masked like Linux
// uid 1000+ accounts.
func winHumanUsers(entries []*entry) []string {
	var out []string
	for _, e := range entries {
		if e.Op != "winuser" || e.data == nil {
			continue
		}
		var users []WinUser
		if json.Unmarshal(e.data, &users) != nil {
			continue
		}
		for _, u := range users {
			i := strings.LastIndexByte(u.SID, '-')
			if rid, err := strconv.Atoi(u.SID[i+1:]); i >= 0 && err == nil && rid >= 1000 {
				out = append(out, u.Name)
			}
		}
	}
	return out
}
