package tools

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// winLogChannels are the event logs log_search may read on Windows.
var winLogChannels = []string{"Security", "System", "Application", "OpenSSH/Operational"}

const (
	winLogDays    = 7     // how far back log_search looks
	winLogScanned = 20000 // events read at most per search
)

// winEventText streams the events of a channel as text lines; tests
// replace it.
var winEventText = func(channel, xpath string, max int, f func(string) bool) error {
	l, ok := winSource().(interface {
		EachEventText(channel, xpath string, max int, f func(string) bool) error
	})
	if !ok {
		return errors.New("not a Windows source")
	}
	return l.EachEventText(channel, xpath, max, f)
}

// winLogSearch is log_search on Windows: path names an event log (one of
// winLogChannels) and the pattern is matched against each event as one
// line (time, channel, ID, Name=value fields; secrets masked; a failed
// logon's typed name never included). The newest matches come back,
// newest first, from the last winLogDays days.
func winLogSearch(channel, pattern string, limit int) (map[string]any, error) {
	ok := false
	for _, c := range winLogChannels {
		if strings.EqualFold(c, channel) {
			channel, ok = c, true
		}
	}
	if !ok {
		return nil, errors.New("on Windows, path is an event log: one of " + strings.Join(winLogChannels, ", "))
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	xpath := fmt.Sprintf("*[System[TimeCreated[timediff(@SystemTime) <= %d]]]", int64(winLogDays)*24*3600*1000)
	hits := []string{}
	err = winEventText(channel, xpath, winLogScanned, func(l string) bool {
		if re.MatchString(l) {
			hits = append(hits, Cut(l, 500))
		}
		return len(hits) < limit
	})
	if err != nil {
		return nil, fmt.Errorf("event log %s could not be read (Shentu must run elevated for Security): %w", channel, err)
	}
	if len(hits) == 0 {
		hits = nil
	}
	return map[string]any{"path": channel, "matches": hits, "window_days": winLogDays, "order": "newest first"}, nil
}
