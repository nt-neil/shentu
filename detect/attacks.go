package detect

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nt-neil/shentu/internal/osutil"
)

// The aggregation of attempts (plan 0743f0, P4 part 2): one group per
// (source network, vulnerability, level, whether its source is believed),
// notified at most once in NotifyEvery, kept in state_dir/attacks.json.
const (
	AttacksFile     = "attacks.json"
	AttacksLock     = "attacks.lock"
	AttackTTL       = 7 * 24 * time.Hour // a group not seen this long is dropped
	NotifyEvery     = 24 * time.Hour
	CampaignWindow  = 24 * time.Hour
	MaxGroups       = 4096
	MaxGroupIPs     = 10 // full addresses listed in a group
	MaxGroupSeen    = 64 // distinct addresses counted in a group, past MaxGroupIPs
	MaxGroupSamples = 3
	MaxIPIndex      = 4096 // sources the campaign index keeps
	MaxIPEntries    = 32   // vulnerabilities it keeps per source
	// CampaignEntries: one source (an IPv4 address, an IPv6 /64) trying
	// this many vulnerabilities (L2 or L3, believed) in CampaignWindow is a
	// campaign, a step up in severity.
	CampaignEntries = 3
	// UnknownNotifyAt: Unknown attempts are counted, not notified, unless
	// one sink gets this many within NotifyEvery (a sliding window):
	// padding must not hide an attacker for ever.
	UnknownNotifyAt = 20
	// MaxStateFile bounds what is read of a state file.
	MaxStateFile = 64 << 20
	// PrefixOverflow is the Prefix of a group the pending groups evicted
	// past MaxGroups are merged into, one per (entry, level, belief). Its
	// addresses and severity are many groups' merged (the severity the
	// highest, the addresses the first ten): it is notified, never blocked
	// on. P5 must not offer or apply a block for an overflow group.
	PrefixOverflow = "overflow"
)

// Group is the attempts of one source network on one vulnerability at
// one level, from believed sources or from others (never both). Unknown
// attempts are grouped by sink alone (Prefix "*"), whatever their source:
// their threshold is the sink's.
type Group struct {
	Key    string `json:"key"`
	Prefix string `json:"prefix"` // 203.0.113.0/24, 2001:db8::/64, the address as logged when it is not one, "*", PrefixOverflow
	Entry  string `json:"entry"`
	Level  string `json:"level"`
	// Rules: a code sink's rules, all its attempts' (Attempt.Rules).
	Rules []string `json:"rules,omitempty"`

	CVE string `json:"cve,omitempty"`
	KEV bool   `json:"kev,omitempty"`
	// VersionUnknown: some attempt's installed version could not be placed
	// in the signature's range (said in the alert; the gate is the same).
	VersionUnknown bool   `json:"version_unknown,omitempty"`
	File           string `json:"file,omitempty"`
	Line           int    `json:"line,omitempty"`

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
	// Unverified: the group's sources cannot be believed; Reasons why.
	Unverified bool     `json:"unverified,omitempty"`
	Reasons    []string `json:"reasons,omitempty"`

	Cut           bool     `json:"cut,omitempty"`
	Suspicious    bool     `json:"suspicious,omitempty"`
	Ambiguous     bool     `json:"ambiguous,omitempty"`
	Encoded       bool     `json:"encoded,omitempty"`
	TimedOut      bool     `json:"timed_out,omitempty"`
	HiddenClasses []string `json:"hidden_classes,omitempty"`
	Success       string   `json:"success,omitempty"`       // why L3, the first attempt's (Attempt.Success)
	ForwardedFor  []string `json:"forwarded_for,omitempty"` // X-Forwarded-For notes, at most MaxGroupSamples
	// Merged: for an overflow group, how many groups were merged into it.
	Merged int `json:"merged,omitempty"`
	// ClockSkew: a time of the group was past the clock (the clock was set
	// back): it is notified, and said.
	ClockSkew bool `json:"clock_skew,omitempty"`

	// Notified: when it was last notified; Since: attempts since then (or
	// since First); Recent: an Unknown group's latest UnknownNotifyAt times,
	// oldest first, for its sliding threshold.
	Notified time.Time   `json:"notified,omitempty"`
	Since    int         `json:"since"`
	Recent   []time.Time `json:"recent,omitempty"`
}

// ipRecord is what the campaign index keeps of one source: the
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
	// Overflow: the pending groups evicted past MaxGroups, merged one per
	// (entry, level, belief): notified as the others are.
	Overflow map[string]*Group `json:"overflow,omitempty"`
	// DroppedPending: pending groups merged into Overflow (or, past its
	// own bound, lost) since the last notice (NoticesSent): said apart
	// (NoticeText), never quietly.
	DroppedPending int `json:"dropped_pending,omitempty"`
	// PassTimeouts: rounds in a row given up before their end (PassRound.
	// Abandon); a round read to its end sets it back to 0.
	PassTimeouts int `json:"pass_timeouts,omitempty"`
	// Note says, when not empty, what loading found wrong: a file that did
	// not parse, set aside, or entries dropped. Said by NoticeText. Not saved.
	Note string `json:"-"`

	lock *os.File
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

func emptyAttacks() *Attacks {
	return &Attacks{Version: 1, Groups: map[string]*Group{}, IPs: map[string]*ipRecord{}, Overflow: map[string]*Group{}}
}

// LoadAttacks takes dir's attacks.lock (held until Close: another process
// loading waits, so neither loses the other's counts) and reads dir's
// attacks.json; none is an empty state. The file is opened without
// following a link, must be ours and not writable by others, and is read
// up to MaxStateFile. One that does not parse is renamed aside
// (attacks.json.bad-<time>) and the state starts empty; entries that do
// not hold together (a null group, a record without entries) are dropped.
// Either is said in Note (NoticeText): never taken as "no attacks" quietly.
func LoadAttacks(dir string, now time.Time) (*Attacks, error) {
	a := emptyAttacks()
	lock, err := os.OpenFile(filepath.Join(dir, AttacksLock), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockBounded(lock); err != nil {
		lock.Close()
		return nil, err
	}
	a.lock = lock
	var got Attacks
	note, err := readState(dir, AttacksFile, &got, now)
	if err != nil {
		a.Close()
		return nil, err
	}
	a.Note = note
	if note != "" && got.Version == 0 {
		return a, nil
	}
	dropped := 0
	olds, oldOverflow := map[string][]*Group{}, map[string][]*Group{}
	for k, g := range got.Groups {
		if g == nil || g.Key != k || g.Count < 0 || g.Since < 0 {
			dropped++
			continue
		}
		loadGroup(a.Groups, olds, k, g)
	}
	addOld(a.Groups, olds)
	for k, g := range got.Overflow {
		if g == nil || g.Key != k {
			dropped++
			continue
		}
		loadGroup(a.Overflow, oldOverflow, k, g)
	}
	addOld(a.Overflow, oldOverflow)
	for ip, r := range got.IPs {
		if r == nil || r.Entries == nil {
			dropped++
			continue
		}
		for e, last := range r.Entries {
			if s := oldSinkKey(e); s != e {
				delete(r.Entries, e)
				if last.After(r.Entries[s]) {
					r.Entries[s] = last
				}
			}
		}
		a.IPs[ip] = r
	}
	a.DroppedPending = max(0, got.DroppedPending)
	a.PassTimeouts = max(0, got.PassTimeouts)
	if dropped > 0 {
		a.Note = join(a.Note, fmt.Sprintf("attacks.json held %d entries that did not hold together; they were dropped", dropped))
	}
	return a, nil
}

// oldSinkKey is a campaign entry saved before sinks were keyed by location
// (code:<rule>:<path>:<line>) as its sink's (sinkKey); any other as it is.
func oldSinkKey(e string) string {
	if rest, ok := strings.CutPrefix(e, "code:"); ok {
		if _, p, ok := strings.Cut(rest, ":"); ok && strings.Contains(p, ":") {
			if n, err := strconv.Atoi(p[strings.LastIndex(p, ":")+1:]); err == nil && n > 0 { // a line (#97 review 3, S-1)
				return "code@" + p
			}
		}
	}
	return e
}

// loadGroup puts g in gs under its key, or, saved before sinks were keyed
// by location, in olds under its sink's key (addOld). The key keeps its
// prefix, level and verified flag. An old Unknown group has no File: its
// entry gives it. A group whose entry, File and Line do not name the same
// sink is kept as it is.
func loadGroup(gs map[string]*Group, olds map[string][]*Group, k string, g *Group) {
	if s := oldSinkKey(g.Entry); s != g.Entry {
		file, line := g.File, g.Line
		if file == "" {
			p := strings.TrimPrefix(s, "code@")
			i := strings.LastIndex(p, ":")
			n, err := strconv.Atoi(p[i+1:])
			if err == nil {
				file, line = p[:i], n
			}
		}
		for _, v := range []bool{true, false} {
			if line > 0 && sinkKey(g.Entry, file, line) == s && k == groupKey(g.Prefix, g.Entry, g.Level, v) {
				k = groupKey(g.Prefix, s, g.Level, v)
				g.File, g.Line = file, line
				if rule, _, ok := strings.Cut(strings.TrimPrefix(g.Entry, "code:"), ":"); ok && len(g.Rules) == 0 {
					g.Rules = []string{rule}
				}
				g.Key = k
				olds[k] = append(olds[k], g)
				return
			}
		}
	}
	gs[k] = g
}

// addOld adds the old groups to gs, a sink's first merged (oldOfSink); into
// a group keyed by the sink (other requests, saved after the upgrade) they
// are added up.
func addOld(gs map[string]*Group, olds map[string][]*Group) {
	for k, og := range olds {
		g := oldOfSink(og)
		d := gs[k]
		if d == nil {
			gs[k] = g
			continue
		}
		n := d.Merged + g.Merged
		mergeLoaded(d, g)
		d.Merged = n
	}
}

// oldOfSink merges one sink's old groups, one per rule for the same
// requests, in the order of their entries (whatever the map's), without
// adding: Count, Since and Merged are the largest, and a time is in Recent
// as often as one group holds it.
func oldOfSink(gs []*Group) *Group {
	slices.SortFunc(gs, func(x, y *Group) int { return strings.Compare(x.Entry, y.Entry) })
	d := gs[0]
	for _, g := range gs[1:] {
		c, s, m := max(d.Count, g.Count), max(d.Since, g.Since), max(d.Merged, g.Merged)
		n := map[time.Time]int{}
		for _, r := range [][]time.Time{d.Recent, g.Recent} {
			per := map[time.Time]int{}
			for _, x := range r {
				per[x.UTC()]++
			}
			for x, c := range per {
				n[x] = max(n[x], c)
			}
		}
		var rec []time.Time
		for x, c := range n {
			for range c {
				rec = append(rec, x)
			}
		}
		slices.SortFunc(rec, func(x, y time.Time) int { return x.Compare(y) })
		if len(rec) > UnknownNotifyAt {
			rec = rec[len(rec)-UnknownNotifyAt:]
		}
		mergeLoaded(d, g)
		d.Count, d.Since, d.Merged, d.Recent = c, s, m, rec
	}
	return d
}

// mergeLoaded merges the loaded group g into d (merge), keeping the later
// notice and the smaller entry.
func mergeLoaded(d, g *Group) {
	d.merge(g)
	if g.Notified.After(d.Notified) {
		d.Notified = g.Notified
	}
	if g.Entry < d.Entry {
		d.Entry = g.Entry
	}
}

// LockTries and LockWait bound the wait for attacks.lock: a stopped
// `shentu detect` (Ctrl-Z) holding it must not stall every patrol after it.
var (
	LockTries = 30
	LockWait  = time.Second
)

// ErrStateLocked: attacks.lock stayed held through LockTries.
var ErrStateLocked = errors.New("attack detection's state is held by another shentu (a stopped `shentu detect`?): this round was skipped")

func lockBounded(f *os.File) error {
	for i := 0; ; i++ {
		err := osutil.TryLock(f)
		if !errors.Is(err, osutil.ErrWouldBlock) {
			return err
		}
		if i+1 >= LockTries {
			return ErrStateLocked
		}
		time.Sleep(LockWait)
	}
}

// AttacksExist says whether dir has attacks.json: none means detection has
// not run yet, not "no attacks".
func AttacksExist(dir string) bool {
	_, err := os.Lstat(filepath.Join(dir, AttacksFile))
	return err == nil
}

// ReadStateFile reads dir/name as the state files are read: not following
// a link, ours and not writable by others, at most max bytes (more is an
// error). A file not there is fs.ErrNotExist.
func ReadStateFile(dir, name string, max int64) ([]byte, error) {
	f, err := openNoFollow(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if why := ownedByUs(st); why != "" {
		return nil, fmt.Errorf("%s: %s", name, why)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s: larger than %d bytes", name, max)
	}
	return b, nil
}

// Close releases attacks.lock; it may be called more than once.
func (a *Attacks) Close() error {
	if a.lock == nil {
		return nil
	}
	osutil.Unlock(a.lock)
	err := a.lock.Close()
	a.lock = nil
	return err
}

func join(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// readState reads dir/name into v the way LoadCursors reads cursors.json:
// opened without following a link, ours and not writable by others, at
// most MaxStateFile. A file that does not parse (or of another version)
// is renamed aside and said in note; v is then left as it was.
func readState(dir, name string, v any, now time.Time) (note string, err error) {
	p := filepath.Join(dir, name)
	f, err := openNoFollow(p) // a link is refused by the open itself
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if why := ownedByUs(st); why != "" {
		return "", fmt.Errorf("%s: %s", name, why)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxStateFile+1))
	if err != nil {
		return "", err
	}
	var ver struct {
		Version int `json:"version"`
	}
	perr := json.Unmarshal(b, &ver)
	if perr == nil && ver.Version == 1 && len(b) <= MaxStateFile {
		if perr = json.Unmarshal(b, v); perr == nil {
			return "", nil
		}
	}
	bad := p + ".bad-" + strconv.FormatInt(now.UnixNano(), 10)
	if rerr := os.Rename(p, bad); rerr != nil {
		return "", errors.Join(perr, rerr)
	}
	keepBad(p, MaxBadFiles)
	return name + " did not parse (or was of another version, or too large) and was set aside as " + filepath.Base(bad) + "; it starts again", nil
}

// MaxBadFiles is how many set-aside copies of a state file are kept, the
// latest: what a file that did not parse held stays to be looked at,
// without filling the disk.
const MaxBadFiles = 5

// keepBad removes all but the latest n of p's set-aside copies.
func keepBad(p string, n int) {
	old, _ := filepath.Glob(globEscape(p) + ".bad-*")
	sort.Slice(old, func(i, j int) bool { // by the time in the name: newest first
		a, _ := strconv.ParseInt(old[i][strings.LastIndex(old[i], "-")+1:], 10, 64)
		b, _ := strconv.ParseInt(old[j][strings.LastIndex(old[j], "-")+1:], 10, 64)
		return a > b
	})
	for _, f := range old[min(n, len(old)):] {
		os.Remove(f)
	}
}

// Save writes the state to dir, pruned (prune): to a new temporary file
// (created exclusively, mode 0600), synced, renamed over the old one, and
// the directory synced. The lock is kept until Close.
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
	return dirSynced(dir)
}

// NetworkOf is the source network an address is grouped by: its /24
// (IPv4) or /64 (IPv6); the text as given, cut to 64 bytes, when it is
// not an address.
func NetworkOf(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Zone() != "" {
		return cutUTF8(ip, 64)
	}
	addr = addr.Unmap()
	bits := 64
	if addr.Is4() {
		bits = 24
	}
	p, _ := addr.Prefix(bits)
	return p.String()
}

// MaxNonIPPrefixes bounds the sources that are not addresses (a client
// field holding text): past it they share one, PrefixNonIP.
const (
	MaxNonIPPrefixes = 64
	PrefixNonIP      = "non-ip"
)

// nonIP is prefix, a source that is not an address, or PrefixNonIP once
// MaxNonIPPrefixes others have groups.
func (a *Attacks) nonIP(prefix string) string {
	seen := map[string]bool{}
	for _, g := range a.Groups {
		if g.Prefix == prefix {
			return prefix
		}
		if _, err := netip.ParsePrefix(g.Prefix); err != nil && g.Prefix != "*" && g.Prefix != PrefixNonIP {
			seen[g.Prefix] = true
		}
	}
	if len(seen) >= MaxNonIPPrefixes {
		return PrefixNonIP
	}
	return prefix
}

func groupKey(prefix, entry, level string, verified bool) string {
	v := "v"
	if !verified {
		v = "u"
	}
	return prefix + "|" + entry + "|" + level + "|" + v
}

// Add counts one attempt. at is its time when the record has none.
func (a *Attacks) Add(t Attempt, at time.Time) *Group {
	if !t.Time.IsZero() {
		at = t.Time
	}
	prefix := NetworkOf(t.IP)
	if t.Level == LevelUnknown {
		prefix = "*"
	} else if _, err := netip.ParsePrefix(prefix); err != nil {
		prefix = a.nonIP(prefix)
	}
	key := groupKey(prefix, sinkKey(t.Entry, t.File, t.Line), t.Level, t.Verified)
	g := a.Groups[key]
	if g == nil {
		if len(a.Groups) >= MaxGroups+MaxGroups/4 { // bounded between saves too
			a.evict(MaxGroups - 1)
		}
		g = &Group{Key: key, Prefix: prefix, Entry: t.Entry, Level: t.Level, CVE: t.CVE, KEV: t.KEV, File: t.File, Line: t.Line, First: at, Last: at}
		a.Groups[key] = g
	}
	g.add(t, at)
	campaign := a.campaign(t, at)
	g.Campaign = g.Campaign || campaign
	if s := t.SeverityWith(campaign); severityIndex(s) > severityIndex(g.Severity) {
		g.Severity = s
	}
	return g
}

// add counts t in g (campaign aside).
func (g *Group) add(t Attempt, at time.Time) {
	if at.Before(g.First) {
		g.First = at
	}
	if at.After(g.Last) {
		g.Last = at
	}
	g.Count++
	g.Since++
	if g.Level == LevelUnknown {
		i, _ := slices.BinarySearchFunc(g.Recent, at, func(x, y time.Time) int { return x.Compare(y) })
		g.Recent = slices.Insert(g.Recent, i, at)
		if len(g.Recent) > UnknownNotifyAt {
			g.Recent = g.Recent[len(g.Recent)-UnknownNotifyAt:]
		}
	}
	g.addIP(t.IP)
	g.addRules(t.Rules)
	if t.Sample != "" && !slices.Contains(g.Samples, t.Sample) { // the latest kept: early neutral requests cannot fill them for good
		g.Samples = append(g.Samples, t.Sample)
		if len(g.Samples) > MaxGroupSamples {
			g.Samples = g.Samples[len(g.Samples)-MaxGroupSamples:]
		}
	}
	if !t.Verified {
		g.Unverified = true
		if t.Reason != "" && !slices.Contains(g.Reasons, t.Reason) && len(g.Reasons) < 4 {
			g.Reasons = append(g.Reasons, t.Reason)
		}
	}
	g.Cut, g.Suspicious, g.Ambiguous = g.Cut || t.Cut, g.Suspicious || t.Suspicious, g.Ambiguous || t.Ambiguous
	g.Encoded, g.TimedOut = g.Encoded || t.Encoded, g.TimedOut || t.TimedOut
	g.VersionUnknown = g.VersionUnknown || t.VersionUnknown
	for _, c := range t.HiddenClasses {
		if !slices.Contains(g.HiddenClasses, c) {
			g.HiddenClasses = append(g.HiddenClasses, c)
		}
	}
	sort.Strings(g.HiddenClasses)
	if g.Success == "" {
		g.Success = t.Success
	}
	if t.ForwardedFor != "" && len(g.ForwardedFor) < MaxGroupSamples && !slices.Contains(g.ForwardedFor, t.ForwardedFor) {
		g.ForwardedFor = append(g.ForwardedFor, t.ForwardedFor)
	}
}

// pending: g has attempts not yet notified that will be (L1 never is: it
// is counted and reported, so it is never "pending", never pushed out
// first, never counted as dropped).
func (g *Group) pending() bool {
	if g.Since == 0 || g.Level == LevelRoute {
		return false
	}
	return g.Level != LevelUnknown || g.unknownDue() // an Unknown group below its threshold is not to be notified
}

// unknownDue: an Unknown group's latest UnknownNotifyAt fall within
// NotifyEvery (Due's threshold).
func (g *Group) unknownDue() bool {
	return len(g.Recent) >= UnknownNotifyAt && g.Recent[len(g.Recent)-1].Sub(g.Recent[0]) <= NotifyEvery
}

// addIP lists ip (at most MaxGroupIPs) and counts it if new.
func (g *Group) addIP(ip string) {
	sum := ipSum(ip)
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

// merge adds src's counts to the overflow group g.
func (g *Group) merge(src *Group) {
	if src.First.Before(g.First) || g.First.IsZero() {
		g.First = src.First
	}
	if src.Last.After(g.Last) {
		g.Last = src.Last
	}
	g.Count += src.Count
	g.Since += src.Since
	g.Merged++
	for _, ip := range src.IPs {
		g.addIP(ip)
	}
	// The addresses past src's listed ones go on being counted and, by
	// hash, known: an address past the cap stays one the gate refuses.
	for _, sum := range src.Seen {
		if !slices.Contains(g.Seen, sum) {
			g.IPsSeen++
			if len(g.Seen) < MaxGroupSeen {
				g.Seen = append(g.Seen, sum)
			}
		}
	}
	if past := src.IPsSeen - max(len(src.Seen), len(src.IPs)); past > 0 { // past even the hashes
		g.IPsSeen += past
	}
	g.IPsSeen = max(g.IPsSeen, len(g.IPs))
	g.addRules(src.Rules)
	for _, s := range src.Samples {
		if len(g.Samples) < MaxGroupSamples && !slices.Contains(g.Samples, s) {
			g.Samples = append(g.Samples, s)
		}
	}
	for _, r := range src.Reasons {
		if len(g.Reasons) < 4 && !slices.Contains(g.Reasons, r) {
			g.Reasons = append(g.Reasons, r)
		}
	}
	for _, t := range src.Recent { // an Unknown group's threshold carries over
		i, _ := slices.BinarySearchFunc(g.Recent, t, func(x, y time.Time) int { return x.Compare(y) })
		g.Recent = slices.Insert(g.Recent, i, t)
	}
	if len(g.Recent) > UnknownNotifyAt {
		g.Recent = g.Recent[len(g.Recent)-UnknownNotifyAt:]
	}
	g.Unverified = g.Unverified || src.Unverified
	g.Campaign = g.Campaign || src.Campaign
	g.Cut, g.Suspicious, g.Ambiguous = g.Cut || src.Cut, g.Suspicious || src.Suspicious, g.Ambiguous || src.Ambiguous
	g.Encoded, g.TimedOut = g.Encoded || src.Encoded, g.TimedOut || src.TimedOut
	if severityIndex(src.Severity) > severityIndex(g.Severity) {
		g.Severity = src.Severity
	}
	if g.Success == "" {
		g.Success = src.Success
	}
}

// addRules adds rules to g's, in order, at most MaxGroupRules.
func (g *Group) addRules(rules []string) {
	for _, r := range rules {
		if !slices.Contains(g.Rules, r) && len(g.Rules) < MaxGroupRules {
			g.Rules = append(g.Rules, r)
		}
	}
	slices.Sort(g.Rules)
}

// MaxGroupRules bounds Group.Rules.
const MaxGroupRules = 16

// campaign records a believed L2 or L3 attempt in the index and says
// whether its source (campaignSource) tried CampaignEntries or more
// vulnerabilities in CampaignWindow. An attempt whose source is not
// believed is neither recorded nor counted: a forged one must not raise a
// real one.
func (a *Attacks) campaign(t Attempt, at time.Time) bool {
	if !t.Verified || t.IP == "" || t.Entry == "" || (t.Level != LevelPayload && t.Level != LevelSuccess) {
		return false
	}
	src := campaignSource(t.IP)
	r := a.IPs[src]
	if r == nil {
		if len(a.IPs) >= MaxIPIndex {
			a.evictIP()
		}
		r = &ipRecord{Entries: map[string]time.Time{}}
		a.IPs[src] = r
	}
	for e, last := range r.Entries {
		if at.Sub(last) > CampaignWindow {
			delete(r.Entries, e)
		}
	}
	sink := sinkKey(t.Entry, t.File, t.Line) // one sink, one entry, however many rules flag it
	if _, ok := r.Entries[sink]; !ok && len(r.Entries) >= MaxIPEntries {
		oldest := ""
		for e, last := range r.Entries {
			if oldest == "" || last.Before(r.Entries[oldest]) || last.Equal(r.Entries[oldest]) && e < oldest {
				oldest = e
			}
		}
		delete(r.Entries, oldest)
	}
	if at.After(r.Entries[sink]) {
		r.Entries[sink] = at
	}
	if at.After(r.Last) {
		r.Last = at
	}
	return len(r.Entries) >= CampaignEntries
}

// listsAny: g lists an address that may be one of wants, however it was
// logged (looseForms).
func listsAny(g *Group, wants map[string]bool) bool {
	for _, x := range g.IPs {
		for f := range looseForms(x) {
			if wants[f] {
				return true
			}
		}
	}
	return false
}

// looseForms are the addresses a source as logged may stand for, each in
// canonAddr's form: brackets, a port and a zone taken off; an IPv4
// address with leading zeros read both as decimal and as octal; an IPv4
// address embedded in IPv6 (::ffff:a.b.c.d, ::a.b.c.d, 64:ff9b::a.b.c.d)
// as itself too. A text that is none of these stands for itself.
func looseForms(s string) map[string]bool {
	out := map[string]bool{s: true, canonAddr(s): true}
	t := strings.TrimSpace(s)
	if strings.HasPrefix(t, "[") {
		if end := strings.IndexByte(t, ']'); end > 0 {
			t = t[1:end]
		}
	} else if host, port, ok := strings.Cut(t, ":"); ok && !strings.Contains(port, ":") && strings.Count(host, ".") == 3 {
		t = host // a.b.c.d:port
	}
	if i := strings.IndexByte(t, '%'); i >= 0 {
		t = t[:i]
	}
	add := func(a netip.Addr) {
		a = a.Unmap()
		out[a.String()] = true
		if a.Is6() {
			b := a.As16()
			var zero [12]byte
			if ([12]byte(b[:12]) == zero && (b[12] != 0 || b[13] != 0)) || [12]byte(b[:12]) == [12]byte{0, 0x64, 0xff, 0x9b} {
				out[netip.AddrFrom4([4]byte(b[12:])).String()] = true
			}
		}
	}
	if a, err := netip.ParseAddr(t); err == nil {
		add(a)
		return out
	}
	if a, ok := inetAton(t); ok {
		out[a.String()] = true
	}
	parts := strings.Split(t, ".")
	if len(parts) != 4 {
		return out
	}
	for _, base := range []int{10, 8} {
		var b [4]byte
		ok := true
		for i, part := range parts {
			n, err := strconv.ParseUint(part, base, 8)
			if base == 8 && (len(part) < 2 || part[0] != '0') {
				n, err = strconv.ParseUint(part, 10, 8) // no leading zero: decimal either way
			}
			if part == "" || err != nil {
				ok = false
				break
			}
			b[i] = byte(n)
		}
		if ok {
			out[netip.AddrFrom4(b).String()] = true
		}
	}
	return out
}

// inetAton reads s as inet_aton does: one to four parts, each decimal,
// octal after a 0 or hexadecimal after 0x, the last filling the bytes left
// (3405803788, 203.29452, 203.0.28940, 0xcb.0.113.12).
func inetAton(s string) (netip.Addr, bool) {
	parts := strings.Split(s, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false
	}
	var v [4]uint64
	for i, part := range parts {
		n, err := strconv.ParseUint(part, 0, 32)
		low := strings.ToLower(part)
		if part == "" || part[0] == '+' || strings.Contains(part, "_") || strings.HasPrefix(low, "0b") || strings.HasPrefix(low, "0o") || err != nil {
			return netip.Addr{}, false
		}
		v[i] = n
	}
	last := len(parts) - 1
	for i := 0; i < last; i++ {
		if v[i] > 0xff {
			return netip.Addr{}, false
		}
	}
	if v[last] >= 1<<(8*(4-last)) {
		return netip.Addr{}, false
	}
	var b [4]byte
	for i := 0; i < last; i++ {
		b[i] = byte(v[i])
	}
	for i := 3; i >= last; i-- {
		b[i] = byte(v[last])
		v[last] >>= 8
	}
	return netip.AddrFrom4(b), true
}

// ipSum is the hash a group keeps of an address (Seen), of its one form:
// ::ffff:192.0.2.1 is 192.0.2.1.
func ipSum(ip string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(canonAddr(ip)))
	return h.Sum32()
}

// canonAddr is ip in one form: unmapped, as netip prints it; the text as
// given when it is not an address.
func canonAddr(ip string) string {
	if a, err := netip.ParseAddr(ip); err == nil && a.Zone() == "" {
		return a.Unmap().String()
	}
	return ip
}

// campaignSource is the campaign index's key for an address: an IPv4
// address itself, an IPv6 address's /64 (one host has many in it).
func campaignSource(ip string) string {
	if addr, err := netip.ParseAddr(ip); err == nil && !addr.Unmap().Is4() {
		return NetworkOf(ip)
	}
	return ip
}

// evictIP drops the source of the index that tried the fewest
// vulnerabilities, the least recently seen of them: a flood of sources
// trying one each pushes out its own before one nearing a campaign.
func (a *Attacks) evictIP() {
	worst := ""
	for ip, r := range a.IPs {
		if worst == "" {
			worst = ip
			continue
		}
		w := a.IPs[worst]
		switch {
		case len(r.Entries) != len(w.Entries):
			if len(r.Entries) < len(w.Entries) {
				worst = ip
			}
		case !r.Last.Equal(w.Last):
			if r.Last.Before(w.Last) {
				worst = ip
			}
		case ip < worst:
			worst = ip
		}
	}
	delete(a.IPs, worst)
}

// evict keeps n groups. The ones dropped first are those with nothing
// left to notify, then unverified ones, then the least severe; among
// pending ones the newest first (a flood of new groups, even pending and
// severe ones from many networks, goes before an older one), among the
// others the least recently seen. A pending one is not lost: it is merged
// into its (entry, level, belief) overflow group, notified as the others,
// and counted in DroppedPending.
func (a *Attacks) evict(n int) {
	if len(a.Groups) <= n {
		return
	}
	if a.Overflow == nil {
		a.Overflow = map[string]*Group{}
	}
	keys := rank(a.Groups)
	for _, k := range keys[n:] {
		g := a.Groups[k]
		if g.pending() {
			a.DroppedPending++
			ok := groupKey(PrefixOverflow, sinkKey(g.Entry, g.File, g.Line), g.Level, !g.Unverified)
			o := a.Overflow[ok]
			if o == nil {
				o = &Group{Key: ok, Prefix: PrefixOverflow, Entry: g.Entry, Level: g.Level, CVE: g.CVE, KEV: g.KEV, File: g.File, Line: g.Line}
				a.Overflow[ok] = o
			}
			o.merge(g)
		}
		delete(a.Groups, k)
	}
	if len(a.Overflow) > MaxGroups { // as many as (entry, level) pairs: past this, lost, and counted
		ks := rank(a.Overflow)
		for _, k := range ks[MaxGroups:] {
			delete(a.Overflow, k)
			a.DroppedPending++
		}
	}
}

// rank orders gs' keys, the one to keep longest first (evict's order).
func rank(gs map[string]*Group) []string {
	keys := make([]string, 0, len(gs))
	for k := range gs {
		keys = append(keys, k)
	}
	keep := func(g *Group) [3]int { // larger is kept longer
		return [3]int{b2i(g.pending()), b2i(!g.Unverified), severityIndex(g.Severity)}
	}
	sort.Slice(keys, func(i, j int) bool {
		x, y := gs[keys[i]], gs[keys[j]]
		if kx, ky := keep(x), keep(y); kx != ky {
			for c := range kx {
				if kx[c] != ky[c] {
					return kx[c] > ky[c]
				}
			}
		}
		if x.pending() { // both pending: the older is kept (a flood is newer than what it would push out)
			if !x.First.Equal(y.First) {
				return x.First.Before(y.First)
			}
		} else if !x.Last.Equal(y.Last) {
			return x.Last.After(y.Last)
		}
		return keys[i] < keys[j]
	})
	return keys
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Due are the groups (and overflow groups) to notify at now: one at L2,
// L3 or Unknown (L1, the route alone, is counted and reported, never
// pushed) not notified in NotifyEvery that has attempts since; an Unknown group only
// once its latest UnknownNotifyAt fall within NotifyEvery. A group last
// notified past now (the clock was set back) is due, its ClockSkew set.
// Noise, unanchored hits and signals are never groups (Round counts them).
func (a *Attacks) Due(now time.Time) []*Group {
	var out []*Group
	for _, gs := range []map[string]*Group{a.Groups, a.Overflow} {
		for _, g := range gs {
			if g.Notified.After(now) {
				g.ClockSkew, g.Notified = true, time.Time{}
			}
			if g.Level == LevelRoute { // L1 is counted and reported, never pushed (plan: alert fatigue)
				continue
			}
			if g.Since == 0 || !g.Notified.IsZero() && now.Sub(g.Notified) < NotifyEvery {
				continue
			}
			if g.Level == LevelUnknown && !g.unknownDue() {
				continue
			}
			out = append(out, g)
		}
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

// The state itself says, apart from any group's alert (NoticeText):
// groups dropped while pending since the last notice, and what loading
// found wrong (Note). NoticesSent says it was sent.

// NoticesSent says NoticeText was sent: the dropped count starts again.
func (a *Attacks) NoticesSent() {
	a.DroppedPending, a.Note = 0, ""
}

// prune drops groups not seen in AttackTTL (one not yet notified is merged
// into its overflow group and counted in DroppedPending), then evicts past
// MaxGroups,
// and drops the campaign index's entries past CampaignWindow. A time past
// now (the clock was set back) is taken as now, and said (ClockSkew).
func (a *Attacks) prune(now time.Time) {
	if a.Overflow == nil {
		a.Overflow = map[string]*Group{}
	}
	for _, gs := range []map[string]*Group{a.Groups, a.Overflow} {
		for k, g := range gs {
			if g.Last.After(now) {
				g.Last, g.ClockSkew = now, true
			}
			if now.Sub(g.Last) <= AttackTTL {
				continue
			}
			if g.pending() { // not yet notified: never dropped quietly
				a.DroppedPending++
				if g.Prefix != PrefixOverflow {
					ok := groupKey(PrefixOverflow, sinkKey(g.Entry, g.File, g.Line), g.Level, !g.Unverified)
					o := a.Overflow[ok]
					if o == nil {
						o = &Group{Key: ok, Prefix: PrefixOverflow, Entry: g.Entry, Level: g.Level, CVE: g.CVE, KEV: g.KEV, File: g.File, Line: g.Line}
						a.Overflow[ok] = o
					}
					o.merge(g)
					o.Last = now // kept until it is notified
				}
			}
			delete(gs, k)
		}
	}
	a.evict(MaxGroups)
	for ip, r := range a.IPs {
		for e, last := range r.Entries {
			if last.After(now) {
				r.Entries[e] = now
				continue
			}
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

// PeekAttacks reads dir's attacks.json for a reader that changes nothing
// (block_ip's gate, attack_attempts, /attacks): without the lock (a patrol
// holding it for its round must not stall them), not following a link,
// ours, bounded. A file that does not parse is an error, left in place.
// None yet: an empty state.
func PeekAttacks(dir string) (*Attacks, error) {
	a := emptyAttacks()
	f, err := openNoFollow(filepath.Join(dir, AttacksFile))
	if errors.Is(err, fs.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", AttacksFile, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if why := ownedByUs(st); why != "" {
		return nil, fmt.Errorf("%s: %s", AttacksFile, why)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxStateFile+1))
	if err != nil {
		return nil, err
	}
	var got Attacks
	if len(b) > MaxStateFile || json.Unmarshal(b, &got) != nil || got.Version != 1 {
		return nil, fmt.Errorf("%s does not parse", AttacksFile)
	}
	for k, g := range got.Groups {
		if g != nil && g.Key == k {
			a.Groups[k] = g
		}
	}
	for k, g := range got.Overflow {
		if g != nil && g.Key == k {
			a.Overflow[k] = g
		}
	}
	return a, nil
}

// GroupsOf are the groups (and overflow groups) listing ip among their
// addresses, an IPv4-mapped address and its IPv4 one being the same.
// MayHold is the groups that do not list ip but may hold it among the
// addresses past their listed ones (MaxGroupIPs): its network's own, one
// whose hashes hold it, and an overflow or sink-wide summary ("*") whose
// hashes were cut too (MaxGroupSeen), whose members cannot be told by
// network. The gate refuses on them as on a group listing it.
func (a *Attacks) MayHold(ip string) []*Group {
	wants := looseForms(ip)
	networks, sums := map[string]bool{}, map[uint32]bool{}
	for w := range wants {
		networks[NetworkOf(w)] = true
		sums[ipSum(w)] = true
		if v4, err := netip.ParseAddr(w); err == nil && v4.Is4() { // as an IPv6 address embedding it is grouped
			b := v4.As4()
			for _, pre := range [][12]byte{{}, {0, 0x64, 0xff, 0x9b}} {
				var a16 [16]byte
				copy(a16[:], pre[:])
				copy(a16[12:], b[:])
				networks[NetworkOf(netip.AddrFrom16(a16).String())] = true
			}
		}
	}
	var out []*Group
	for _, gs := range []map[string]*Group{a.Groups, a.Overflow} {
		for _, g := range gs {
			if g.IPsSeen <= len(g.IPs) || listsAny(g, wants) {
				continue
			}
			hit := networks[g.Prefix]
			for _, sum := range g.Seen {
				hit = hit || sums[sum]
			}
			wide := g.Prefix == PrefixOverflow || g.Prefix == "*"
			if hit || wide && g.IPsSeen > len(g.Seen) {
				out = append(out, g)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func (a *Attacks) GroupsOf(ip string) []*Group {
	wants := looseForms(ip)
	var out []*Group
	for _, gs := range []map[string]*Group{a.Groups, a.Overflow} {
		for _, g := range gs {
			if listsAny(g, wants) {
				out = append(out, g)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
