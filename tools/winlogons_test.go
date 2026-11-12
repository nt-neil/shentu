package tools

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

func TestWinLogonSummary(t *testing.T) {
	ev := func(id int, ip, user string) hostenv.WinEvent {
		return hostenv.WinEvent{Channel: "Security", ID: id, Time: "2026-11-12T15:00:00.1234567Z",
			Data: map[string]string{"IpAddress": ip, "TargetUserName": user, "LogonType": "10"}}
	}
	var gotXPath string
	old := winEvents
	t.Cleanup(func() { winEvents = old })
	winEvents = func(ch, xpath string, max int) ([]hostenv.WinEvent, error) {
		gotXPath = xpath
		return []hostenv.WinEvent{
			ev(4625, "203.0.113.9", ""), ev(4625, "203.0.113.9", ""), ev(4625, "203.0.113.9", ""),
			ev(4624, "203.0.113.9", "admin"),
			ev(4624, "198.51.100.7", "DC01$"),           // a computer account
			ev(4624, "198.51.100.8", "ANONYMOUS LOGON"), // not a person
			ev(4624, "-", "localuser"),                  // not remote
			ev(4625, "-", ""),                           // a failed local logon
		}, nil
	}
	out, err := winLogonSummary(time.Now().Add(-time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotXPath, "EventID=4625") || !strings.Contains(gotXPath, "'10'") {
		t.Errorf("xpath: %s", gotXPath)
	}
	src := out["sources"].([]SSHSource)
	if len(src) != 2 || src[0].IP != "203.0.113.9" || src[0].Failed != 3 || src[0].Accepted != 1 ||
		strings.Join(src[0].AcceptedUsers, ",") != "admin" || src[1].IP != "local" || src[1].Failed != 1 {
		t.Errorf("sources: %+v", src)
	}
	if !strings.Contains(out["source"].(string), "Windows Security log") {
		t.Errorf("the source must say these are Windows logons, not SSH: %v", out["source"])
	}

	out, _ = winLogonSummary(time.Now().Add(-time.Hour), "203.0.113.9")
	if len(out["sources"].([]SSHSource)) != 1 {
		t.Errorf("ip filter: %+v", out["sources"])
	}

	winEvents = func(string, string, int) ([]hostenv.WinEvent, error) { return nil, errors.New("access denied") }
	if out, err := winLogonSummary(time.Now().Add(-time.Hour), ""); err == nil || out != nil {
		t.Error("an unreadable Security log must be an error, never an empty summary")
	}
}
