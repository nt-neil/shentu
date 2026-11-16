package detect

import (
	"encoding/json"
	"errors"
	"hash/fnv"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"time"
)

// The aggregation of attempts (plan 0743f0, P4 part 2): one group per
// (source network, vulnerability, level), notified at most once in
// NotifyEvery, kept in state_dir/attacks.json.
const (
	AttacksFile     = "attacks.json"
	AttackTTL       = 7 * 24 * time.Hour // a group not seen this long is dropped
	NotifyEvery     = 24 * time.Hour
	CampaignWindow  = 24 * time.Hour
	MaxGroups       = 4096
	MaxGroupIPs     = 10 // full addresses listed in a group
	MaxGroupSeen    = 64 // distinct addresses counted in a group, past MaxGroupIPs
	MaxGroupSamples = 3
	MaxIPIndex      = 4096 // addresses the campaign index keeps
	MaxIPEntries    = 32   // vulnerabilities it keeps per address
	// CampaignEntries: one address trying this many vulnerabilities (L2 or
	// L3) in CampaignWindow is a campaign, a step up in severity.
	CampaignEntries = 3
	// UnknownNotifyAt: Unknown attempts are counted, not notified, unless
	// one sink gets this many in NotifyEvery: padding must not hide an
	// attacker for ever.
	UnknownNotifyAt = 20
)

// Group is the attempts of one source network on one vulnerability at
// one level. Unknown attempts are grouped by sink alone (Prefix "*"),
// whatever their source: their threshold is the sink's.
type Group struct {
	Key    string `json:"key"`
	Prefix string `json:"prefix"` // 203.0.113.0/24, 2001:db8::/64, or the address as logged when it is not one
	Entry  string `json:"entry"`
	Level  string `json:"level"`

	CVE  string `json:"cve,omitempty"`
	KEV  bool   `json:"kev,omitempty"`
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`

	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
	Count    int       `json:"count"`
	Severity string    `json:"severity"`
	Campaign bool      `json:"campaign,omitempty"`
	// IPs: the full addresses seen, at most MaxGroupIPs; IPsSeen: how many
	// distinct ones in all (hashes kept in seen, at most MaxGroupSeen: past
	// it IPsSeen is a floor).
	IPs     []string `json:"ips"`
	IPsSeen int      `json:"ips_seen"`
	Seen    []uint32 `json:"seen,omitempty"`
	Samples []string `json:"samples,omitempty"`
	// Unverified: some attempt's IP cannot be believed; Reasons why.
	Unverified bool     `json:"unverified,omitempty"`
	Reasons    []string `json:"reasons,omitempty"`

	Cut           bool     `json:"cut,omitempty"`
	Suspicious    bool     `json:"suspicious,omitempty"`
	Ambiguous     bool     `json:"ambiguous,omitempty"`
	Encoded       bool     `json:"encoded,omitempty"`
	TimedOut      bool     `json:"timed_out,omitempty"`
	HiddenClasses []string `json:"hidden_classes,omitempty"`

	// Notified: when it was last notified; Since: attempts since then (or
	// since First); Window and WindowCount: the attempts of the current
	// NotifyEvery, for an Unknown group's threshold.
	Notified    time.Time `json:"notified,omitempty"`
	Since       int       `json:"since"`
	Window      time.Time `json:"window,omitempty"`
	WindowCount int       `json:"window_count,omitempty"`
}

// ipRecord is what the campaign index keeps of one address: the
// vulnerabilities it tried at L2 or L3, and when last.
type ipRecord struct {
	Entries map[string]time.Time `json:"entries"`
	Last    time.Time            `json:"last"`
}

// Attacks is the state of attacks.json.
type Attacks struct {
	Version int                  `json:"version"`
	Groups  map[string]*Group    `json:"groups"`
	IPs     map[string]*ipRecord `json:"ips"`
	// DroppedPending: groups dropped past MaxGroups while they still had
	// attempts not notified, in all: said, never dropped quietly.
	DroppedPending int `json:"dropped_pending,omitempty"`
	// Note says, when not empty, why the state started empty: the file
	// did not parse and was set aside (its new name in it). Not saved.
	Note string `json:"-"`
}

// Round counts what a pass saw and does not notify: noise, unanchored
// hits, signals, and Unknown attempts (undetermined: neither noise nor
// clean).
type Round struct {
	Noise, Unanchored, Signals, Unknown int
}

// Judged counts what a judgment holds that is never notified.
func (r *Round) Judged(g Judgment) {
	r.Noise += len(g.Noise)
	r.Unanchored += len(g.Unanchored)
	if g.Unknown {
		r.Unknown++
	}
}

// LoadAttacks reads dir's attacks.json; none is an empty state. One that
// does not parse is renamed aside (attacks.json.bad-<unix>) and the state
// starts empty, said in Note: never taken as "no attacks" quietly.
func LoadAttacks(dir string, now time.Time) (*Attacks, error) {
	a := &Attacks{Version: 1, Groups: map[string]*Group{}, IPs: map[string]*ipRecord{}}
	p := filepath.Join(dir, AttacksFile)
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	var got Attacks
	if err := json.Unmarshal(b, &got); err != nil || got.Version != 1 {
		bad := p + ".bad-" + strconv.FormatInt(now.Unix(), 10)
		if rerr := os.Rename(p, bad); rerr != nil {
			return nil, errors.Join(err, rerr)
		}
		a.Note = "attacks.json did not parse and was set aside as " + filepath.Base(bad) + "; counts start again"
		return a, nil
	}
	if got.Groups != nil {
		a.Groups = got.Groups
	}
	if got.IPs != nil {
		a.IPs = got.IPs
	}
	return a, nil
}

// Save writes the state to dir, pruned (prune): to a new temporary file
// (created exclusively, mode 0600), synced, renamed over the old one, and
// the directory synced.
func (a *Attacks) Save(dir string, now time.Time) error {
	a.prune(now)
	a.Version = 1
	return saveJSON(dir, AttacksFile, a)
}

// saveJSON writes v as dir/name the way Cursors.Save does.
func saveJSON(dir, name string, v any) error {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, name+".*.tmp") // O_EXCL, 0600
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(b)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(dir)
}

// NetworkOf is the source network an address is grouped by: its /24
// (IPv4) or /64 (IPv6); the text as given when it is not an address.
func NetworkOf(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	bits := 64
	if addr.Is4() {
		bits = 24
	}
	p, _ := addr.Prefix(bits)
	return p.String()
}

// Add counts one attempt. at is its time when the record has none.
func (a *Attacks) Add(t Attempt, at time.Time) *Group {
	if !t.Time.IsZero() {
		at = t.Time
	}
	prefix := NetworkOf(t.IP)
	if t.Level == LevelUnknown {
		prefix = "*"
	}
	key := prefix + "|" + t.Entry + "|" + t.Level
	g := a.Groups[key]
	if g == nil {
		if len(a.Groups) >= MaxGroups+MaxGroups/4 { // bounded between saves too
			a.evict(MaxGroups - 1)
		}
		g = &Group{Key: key, Prefix: prefix, Entry: t.Entry, Level: t.Level, CVE: t.CVE, KEV: t.KEV, File: t.File, Line: t.Line, First: at, Last: at}
		a.Groups[key] = g
	}
	if at.Before(g.First) {
		g.First = at
	}
	if at.After(g.Last) {
		g.Last = at
	}
	g.Count++
	g.Since++
	if g.Window.IsZero() || at.Sub(g.Window) >= NotifyEvery {
		g.Window, g.WindowCount = at, 0
	}
	g.WindowCount++
	g.addIP(t.IP)
	if len(g.Samples) < MaxGroupSamples && t.Sample != "" && !slices.Contains(g.Samples, t.Sample) {
		g.Samples = append(g.Samples, t.Sample)
	}
	if !t.Verified {
		g.Unverified = true
		if t.Reason != "" && !slices.Contains(g.Reasons, t.Reason) && len(g.Reasons) < 4 {
			g.Reasons = append(g.Reasons, t.Reason)
		}
	}
	g.Cut, g.Suspicious, g.Ambiguous = g.Cut || t.Cut, g.Suspicious || t.Suspicious, g.Ambiguous || t.Ambiguous
	g.Encoded, g.TimedOut = g.Encoded || t.Encoded, g.TimedOut || t.TimedOut
	for _, c := range t.HiddenClasses {
		if !slices.Contains(g.HiddenClasses, c) {
			g.HiddenClasses = append(g.HiddenClasses, c)
		}
	}
	sort.Strings(g.HiddenClasses)
	campaign := a.campaign(t, at)
	g.Campaign = g.Campaign || campaign
	if s := SeverityOf(t.Level, t.Severe, campaign, t.Verified); severityIndex(s) > severityIndex(g.Severity) {
		g.Severity = s
	}
	return g
}

// addIP lists ip (at most MaxGroupIPs) and counts it if new.
func (g *Group) addIP(ip string) {
	h := fnv.New32a()
	h.Write([]byte(ip))
	sum := h.Sum32()
	if slices.Contains(g.Seen, sum) || slices.Contains(g.IPs, ip) {
		return
	}
	g.IPsSeen++
	if len(g.IPs) < MaxGroupIPs {
		g.IPs = append(g.IPs, ip)
	}
	if len(g.Seen) < MaxGroupSeen {
		g.Seen = append(g.Seen, sum)
	}
}

// campaign records an L2 or L3 attempt in the index and says whether its
// address tried CampaignEntries or more vulnerabilities in CampaignWindow.
func (a *Attacks) campaign(t Attempt, at time.Time) bool {
	if t.IP == "" || t.Entry == "" || (t.Level != LevelPayload && t.Level != LevelSuccess) {
		return false
	}
	r := a.IPs[t.IP]
	if r == nil {
		if len(a.IPs) >= MaxIPIndex {
			a.evictIP()
		}
		r = &ipRecord{Entries: map[string]time.Time{}}
		a.IPs[t.IP] = r
	}
	for e, last := range r.Entries {
		if at.Sub(last) > CampaignWindow {
			delete(r.Entries, e)
		}
	}
	if _, ok := r.Entries[t.Entry]; !ok && len(r.Entries) >= MaxIPEntries {
		oldest := ""
		for e, last := range r.Entries {
			if oldest == "" || last.Before(r.Entries[oldest]) || last.Equal(r.Entries[oldest]) && e < oldest {
				oldest = e
			}
		}
		delete(r.Entries, oldest)
	}
	if at.After(r.Entries[t.Entry]) {
		r.Entries[t.Entry] = at
	}
	if at.After(r.Last) {
		r.Last = at
	}
	return len(r.Entries) >= CampaignEntries
}

// evict keeps n groups. The ones dropped first are those with nothing
// left to notify, then unverified ones, then the least severe; among
// pending ones the newest first (a flood of new groups, even pending and
// severe ones from many networks, pushes out its own before an older
// one), among the others the least recently seen. One dropped with
// attempts not notified is counted in DroppedPending, which the report
// and the alert say (alert.go).
func (a *Attacks) evict(n int) {
	if len(a.Groups) <= n {
		return
	}
	keys := make([]string, 0, len(a.Groups))
	for k := range a.Groups {
		keys = append(keys, k)
	}
	keep := func(g *Group) [3]int { // larger is kept longer
		return [3]int{b2i(g.Since > 0), b2i(!g.Unverified), severityIndex(g.Severity)}
	}
	sort.Slice(keys, func(i, j int) bool {
		x, y := a.Groups[keys[i]], a.Groups[keys[j]]
		if kx, ky := keep(x), keep(y); kx != ky {
			for c := range kx {
				if kx[c] != ky[c] {
					return kx[c] > ky[c]
				}
			}
		}
		if x.Since > 0 { // both pending: the older is kept (a flood is newer than what it would push out)
			if !x.First.Equal(y.First) {
				return x.First.Before(y.First)
			}
		} else if !x.Last.Equal(y.Last) {
			return x.Last.After(y.Last)
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys[n:] {
		if a.Groups[k].Since > 0 {
			a.DroppedPending++
		}
		delete(a.Groups, k)
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// evictIP drops the address of the index seen least recently.
func (a *Attacks) evictIP() {
	oldest := ""
	for ip, r := range a.IPs {
		if oldest == "" || r.Last.Before(a.IPs[oldest].Last) || r.Last.Equal(a.IPs[oldest].Last) && ip < oldest {
			oldest = ip
		}
	}
	delete(a.IPs, oldest)
}

// Due are the groups to notify at now, by key: one not notified in
// NotifyEvery that has attempts since; an Unknown group only once it holds
// UnknownNotifyAt in its current window. Noise, unanchored hits and
// signals are never groups (Round counts them).
func (a *Attacks) Due(now time.Time) []*Group {
	var out []*Group
	for _, g := range a.Groups {
		if g.Since == 0 || !g.Notified.IsZero() && now.Sub(g.Notified) < NotifyEvery {
			continue
		}
		if g.Level == LevelUnknown && g.WindowCount < UnknownNotifyAt {
			continue
		}
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := severityIndex(out[i].Severity), severityIndex(out[j].Severity); a != b {
			return a > b
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// Notified says g was notified at now: the count since starts again.
func (a *Attacks) Notified(g *Group, now time.Time) {
	g.Notified, g.Since = now, 0
}

// prune drops groups not seen in AttackTTL, then the least recently seen
// past MaxGroups, and the campaign index's entries past CampaignWindow.
func (a *Attacks) prune(now time.Time) {
	for k, g := range a.Groups {
		if now.Sub(g.Last) > AttackTTL {
			delete(a.Groups, k)
		}
	}
	a.evict(MaxGroups)
	for ip, r := range a.IPs {
		for e, last := range r.Entries {
			if now.Sub(last) > CampaignWindow {
				delete(r.Entries, e)
			}
		}
		if len(r.Entries) == 0 {
			delete(a.IPs, ip)
		}
	}
}

func severityIndex(s string) int { return slices.Index(severities, s) }
