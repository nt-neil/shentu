package tools

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

// winEvents reads one Windows event channel; tests replace it.
var winEvents = func(channel, xpath string, max int) ([]hostenv.WinEvent, error) {
	ws, ok := winSource().(hostenv.WinSource)
	if !ok {
		return nil, errors.New("not a Windows source")
	}
	return ws.Events(channel, xpath, max)
}

// maxListedUsers caps the accounts listed per source.
const maxListedUsers = 10

// logonXPath selects failed logons (4625) and remote successful ones
// (4624 of logon type 3 network, 8 cleartext as OpenSSH uses, 10 RDP)
// since a time.
func logonXPath(since, now time.Time) string {
	ms := max(now.Sub(since).Milliseconds(), 1)
	return fmt.Sprintf("*[System[TimeCreated[timediff(@SystemTime) <= %d]] and (System[EventID=4625] or "+
		"(System[EventID=4624] and EventData[Data[@Name='LogonType']='3' or Data[@Name='LogonType']='8' or Data[@Name='LogonType']='10']))]", ms)
}

// winLogonSummary is ssh_logins on Windows: the Security log's failed and
// remote logons per source address, in the shape of the Linux summary.
// Names typed at a failed logon are not kept (the event parser drops them).
// Computer accounts (NAME$) and anonymous sessions are not logins of a
// person and are left out. An unreadable log is an error, never an empty
// summary.
func winLogonSummary(since time.Time, onlyIP string) (map[string]any, error) {
	evs, err := winEvents("Security", logonXPath(since, time.Now()), hostenv.MaxEvents)
	if err != nil {
		return nil, fmt.Errorf("the Windows Security log could not be read (Shentu must run elevated): %w", err)
	}
	by := map[string]*SSHSource{}
	for _, e := range evs {
		ip := e.Data["IpAddress"]
		if ip == "" || ip == "-" {
			if e.ID == 4624 {
				continue // a local logon, not a remote one
			}
			ip = "local"
		}
		user := e.Data["TargetUserName"]
		if e.ID == 4624 && (strings.HasSuffix(user, "$") || strings.EqualFold(user, "ANONYMOUS LOGON")) {
			continue
		}
		if onlyIP != "" && ip != onlyIP {
			continue
		}
		s := by[ip]
		if s == nil {
			s = &SSHSource{IP: ip}
			by[ip] = s
		}
		if t, err := time.Parse(time.RFC3339Nano, e.Time); err == nil {
			if s.First.IsZero() || t.Before(s.First) {
				s.First = t
			}
			if t.After(s.Last) {
				s.Last = t
			}
		}
		switch e.ID {
		case 4625:
			s.Failed++
		case 4624:
			s.Accepted++
			if user != "" && len(s.AcceptedUsers) < maxListedUsers && !contains(s.AcceptedUsers, user) {
				s.AcceptedUsers = append(s.AcceptedUsers, user)
			}
		}
	}
	list := make([]SSHSource, 0, len(by))
	for _, s := range by {
		list = append(list, *s)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Failed != list[j].Failed {
			return list[i].Failed > list[j].Failed
		}
		return list[i].IP < list[j].IP
	})
	out := map[string]any{
		// Only the system (LSA) writes the Security log, unlike Linux text logs.
		"verified": true,
		"source":   "Windows Security log: failed logons (4625) and network (3), cleartext/OpenSSH (8) and RDP (10) logons (4624)",
		"since":    since,
		"sources":  list,
		// As on Linux: false when the counts are a lower bound.
		"complete": len(evs) < hostenv.MaxEvents,
	}
	if len(evs) >= hostenv.MaxEvents {
		out["note"] = fmt.Sprintf("more than %d matching events: counts are a lower bound", hostenv.MaxEvents)
	}
	return out, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
