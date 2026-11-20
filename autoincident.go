package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nt-neil/shentu/detect"
	"github.com/nt-neil/shentu/internal/osutil"
	"github.com/nt-neil/shentu/tools"
)

// Automatic incident checks (phase 2, C): an L3 alert the patrol pushed
// dispatches the incident sub-agent on its own, read-only, with no one
// asking. Off unless [agents] auto_incident = true.
//
// Limits, all checked before a model is called: one dispatch per patrol
// round (the rest wait in Pending for the next rounds), at most
// autoDailyCap in any autoWindow, a group once per autoWindow, none from
// L3 groups of logs that cannot be believed or from overflow groups, none
// once the month's AI budget is at autoBudgetStop, and none when no monthly
// budget is set. A slot is taken in auto-incident.json before the
// dispatch runs, so a crash cannot give a fourth. What goes out is
// enumerations and numbers only; the sub-agent's proposals are for B's
// buttons, never acted on here.

const (
	autoIncidentFile  = "auto-incident.json"
	autoIncidentLock  = "auto-incident.lock"
	autoDailyCap      = 3
	autoBudgetStop    = 0.8
	autoWindow        = 24 * time.Hour
	autoKeep          = 2 * autoWindow // dispatches and skip counts kept this long
	autoPendingMax    = 20
	autoIncidentHours = 24 // the sub-agent's look-back
	autoStateMax      = 256 << 10
)

// Why an L3 alert was not dispatched (autoState.Skipped). Fixed words.
const (
	autoSkipNoBudget   = "no_budget"  // no monthly budget is set
	autoSkipBudget     = "budget"     // the month's budget is at autoBudgetStop
	autoSkipDailyCap   = "daily_cap"  // autoDailyCap in the last autoWindow
	autoSkipGroup      = "group"      // this group was dispatched for in the last autoWindow
	autoSkipUnverified = "unverified" // an L3 group of logs that cannot be believed
	autoSkipOverflow   = "overflow"   // an overflow group: no one source network
	autoSkipNoIP       = "no_ip"      // the group lists no usable address
	autoSkipQueueFull  = "queue_full" // autoPendingMax were already waiting
	autoSkipExpired    = "expired"    // waited longer than autoWindow
	autoSkipArchive    = "archive"    // the dispatch archive could not be read: its count is unknown
)

var autoSkipOrder = []string{autoSkipNoBudget, autoSkipBudget, autoSkipDailyCap, autoSkipGroup, autoSkipUnverified,
	autoSkipOverflow, autoSkipNoIP, autoSkipQueueFull, autoSkipExpired, autoSkipArchive}

// autoState is auto-incident.json.
type autoState struct {
	V          int                       `json:"v"`
	Dispatches []autoSlot                `json:"dispatches"` // slots taken, oldest first
	Pending    []autoPending             `json:"pending"`
	Skipped    map[string]map[string]int `json:"skipped"` // UTC hour "2006-01-02T15" -> reason -> count
}

// autoSlot is one dispatch: taken (ID "") before it runs, filled in after.
type autoSlot struct {
	TS      time.Time `json:"ts"`
	Trigger string    `json:"trigger"`
	ID      string    `json:"id,omitempty"`
	Status  string    `json:"status,omitempty"`
}

// autoPending is an L3 alert waiting for a round with no dispatch yet.
type autoPending struct {
	Trigger string    `json:"trigger"`
	IP      string    `json:"ip"`
	Seen    time.Time `json:"seen"`
}

// autoArchive is the part of the dispatch archive (A) C reads; runDispatch
// writes it.
type autoArchive interface {
	AutoSince(t time.Time) (int, map[string]bool, error)
}

// Seams for tests.
var (
	autoStore     = func(cfg *Config) autoArchive { return newDispatchStore(cfg) }
	autoLockTries = 10
	autoLockWait  = time.Second
)

// autoCandidate is an L3 group the patrol pushed this round.
type autoCandidate struct {
	Trigger, IP string
	skip        string // set: not dispatched, counted under this reason
}

// autoCandidateOf says whether a pushed group may be dispatched for. Only
// L3 is; an L3 group of logs that cannot be believed is refused here even
// though detect.Upgrade gives none today (C4).
func autoCandidateOf(g *detect.Group) (autoCandidate, bool) {
	if g.Level != detect.LevelSuccess {
		return autoCandidate{}, false
	}
	c := autoCandidate{Trigger: g.Key}
	switch {
	case g.Unverified:
		c.skip = autoSkipUnverified
	case g.Prefix == detect.PrefixOverflow:
		c.skip = autoSkipOverflow
	default:
		for _, s := range g.IPs {
			if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
				c.IP = ip.String()
				break
			}
		}
		if c.IP == "" {
			c.skip = autoSkipNoIP
		}
	}
	return c, true
}

// autoIncident is the round's part of C, after the alerts went and the
// attack state was saved: queue this round's L3 groups, then dispatch for
// at most one. It returns the dispatch id, "" for none.
func autoIncident(ctx context.Context, cfg *Config, env *tools.Env, cands []autoCandidate, now time.Time) (string, error) {
	if !cfg.Agents.AutoIncident {
		return "", nil
	}
	pick, err := autoReserve(cfg, cands, now)
	if err != nil || pick == nil {
		return "", err
	}
	rec, err := autoRun(ctx, cfg, env, *pick)
	ferr := autoFinish(cfg, *pick, rec, now)
	if err != nil {
		return rec.ID, errors.Join(err, ferr)
	}
	nerr := detectNotify(ctx, env, "Automatic incident check", autoNotice(rec), "warning")
	return rec.ID, errors.Join(ferr, nerr)
}

// autoReserve queues cands and, when every limit allows, takes a slot for
// the first waiting alert and returns it.
func autoReserve(cfg *Config, cands []autoCandidate, now time.Time) (*autoPending, error) {
	var pick *autoPending
	err := withAutoState(cfg.StateDir, now, func(st *autoState) {
		for _, c := range cands {
			switch {
			case c.skip != "":
				st.skip(now, c.skip)
			case st.waiting(c.Trigger):
			case len(st.Pending) >= autoPendingMax:
				st.skip(now, autoSkipQueueFull)
			default:
				st.Pending = append(st.Pending, autoPending{Trigger: c.Trigger, IP: c.IP, Seen: now})
			}
		}
		var keep []autoPending
		for _, p := range st.Pending {
			if now.Sub(p.Seen) > autoWindow {
				st.skip(now, autoSkipExpired)
			} else {
				keep = append(keep, p)
			}
		}
		st.Pending = keep
		if len(st.Pending) == 0 {
			return
		}
		dropAll := func(why string) {
			for range st.Pending {
				st.skip(now, why)
			}
			st.Pending = nil
		}
		if cfg.Budget.MonthlyCost <= 0 && cfg.Budget.MonthlyTokens <= 0 {
			dropAll(autoSkipNoBudget)
			return
		}
		if budgetUsed(cfg, now) >= autoBudgetStop {
			dropAll(autoSkipBudget)
			return
		}
		since := now.Add(-autoWindow)
		n, triggers, err := autoStore(cfg).AutoSince(since)
		if err != nil {
			dropAll(autoSkipArchive)
			return
		}
		if triggers == nil {
			triggers = map[string]bool{}
		}
		taken := 0
		for _, d := range st.Dispatches {
			if !d.TS.Before(since) {
				taken++
				triggers[triggerID(d.Trigger)] = true
			}
		}
		if max(n, taken) >= autoDailyCap {
			dropAll(autoSkipDailyCap)
			return
		}
		for len(st.Pending) > 0 {
			p := st.Pending[0]
			st.Pending = st.Pending[1:]
			if triggers[triggerID(p.Trigger)] {
				st.skip(now, autoSkipGroup)
				continue
			}
			st.Dispatches = append(st.Dispatches, autoSlot{TS: now, Trigger: p.Trigger})
			pick = &p
			return
		}
	})
	if err != nil {
		return nil, err
	}
	return pick, nil
}

// autoRun dispatches the incident sub-agent for p; runDispatch archives
// it. The record returned is for the notice.
func autoRun(ctx context.Context, cfg *Config, env *tools.Env, p autoPending) (dispatchRecord, error) {
	args, _ := json.Marshal(map[string][]subTask{"tasks": {{Role: "incident", IP: p.IP, Hours: autoIncidentHours}}})
	tasks, err := parseTasks(args)
	if err != nil {
		return dispatchRecord{}, err
	}
	a := &agent{cfg: cfg, llm: newLLM(cfg), env: env, actor: "auto", log: newAuditLog(cfg.StateDir)}
	start := time.Now()
	id, reps := a.runDispatch(ctx, originAuto, p.Trigger, tasks)
	used := 0
	for _, r := range reps {
		used += r.Tokens
	}
	a.log.write(logEntry{Actor: a.actor, Tool: "dispatch", Args: mask(string(args)), Dispatch: id, Origin: originAuto, OK: true})
	return newDispatchRecord(id, originAuto, p.Trigger, start, used, dispatchTokenCap, reps), nil
}

// autoFinish writes the dispatch's id and status into its slot.
func autoFinish(cfg *Config, p autoPending, rec dispatchRecord, now time.Time) error {
	return withAutoState(cfg.StateDir, now, func(st *autoState) {
		for i := len(st.Dispatches) - 1; i >= 0; i-- {
			if d := &st.Dispatches[i]; d.Trigger == p.Trigger && d.ID == "" {
				d.ID, d.Status = rec.ID, rec.Status
				return
			}
		}
	})
}

// autoNotice is the alert about a finished dispatch: enumerations and
// numbers from its record only, never a sub-agent's words.
func autoNotice(rec dispatchRecord) string {
	var b strings.Builder
	fmt.Fprintf(&b, "An L3 attack alert was checked by the incident sub-agent on its own (read-only; nothing was changed).\n- dispatch: %s\n- status: %s\n", rec.ID, word(rec.Status))
	for _, s := range rec.Subs {
		fmt.Fprintf(&b, "- %s: %s (%s), %d steps, %d tokens\n", word(s.Role), word(s.Status), word(s.Reason), s.Steps, s.TokensIn+s.TokensOut+s.TokensReason)
		var sev []string
		for _, k := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
			if n := s.Findings[k]; n > 0 {
				sev = append(sev, fmt.Sprintf("%s %d", k, n))
			}
		}
		if len(sev) == 0 {
			sev = []string{"none"}
		}
		fmt.Fprintf(&b, "- findings: %s; not checked: %d; proposals: %d (not acted on)\n", strings.Join(sev, ", "), s.Unchecked, len(s.Proposals))
	}
	if rec.Status != statusComplete {
		b.WriteString("- an incomplete check is not a clean one: what it did not check is unknown\n")
	}
	return b.String()
}

// word keeps an enumeration's characters only: a record read back is
// untrusted, and its fields were checked against their patterns by Save.
func word(s string) string {
	s = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			return r
		}
		return -1
	}, s)
	if s == "" || len(s) > 32 {
		return "?"
	}
	return s
}

// autoIncidentSection is the daily report's lines about C for the last
// autoWindow: dispatches and every reason one was not made, the missing
// budget said first. "" when C is off.
func autoIncidentSection(cfg *Config, now time.Time) string {
	if !cfg.Agents.AutoIncident {
		return ""
	}
	var b strings.Builder
	b.WriteString("\nAutomatic incident checks (L3 alerts, read-only, last day):\n")
	if cfg.Budget.MonthlyCost <= 0 && cfg.Budget.MonthlyTokens <= 0 {
		b.WriteString("- none are made: no monthly AI budget is set ([budget] monthly_cost or monthly_tokens)\n")
	}
	st, err := readAutoState(cfg.StateDir)
	if err != nil {
		fmt.Fprintf(&b, "- not known: %s could not be read (%s)\n", autoIncidentFile, mask(err.Error()))
		return b.String()
	}
	since := now.Add(-autoWindow)
	n, incomplete := 0, 0
	for _, d := range st.Dispatches {
		if !d.TS.Before(since) {
			n++
			if d.Status != statusComplete {
				incomplete++
			}
		}
	}
	fmt.Fprintf(&b, "- dispatched: %d of at most %d (not complete: %d)\n", n, autoDailyCap, incomplete)
	counts := st.skippedSince(since)
	var parts []string
	for _, k := range autoSkipOrder {
		if counts[k] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", k, counts[k]))
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(&b, "- not dispatched: %s\n", strings.Join(parts, ", "))
	}
	if counts[autoSkipBudget] > 0 {
		fmt.Fprintf(&b, "- the month's AI budget reached %d%%: automatic checks stopped until next month\n", int(autoBudgetStop*100))
	}
	if len(st.Pending) > 0 {
		fmt.Fprintf(&b, "- waiting for a later round: %d\n", len(st.Pending))
	}
	return b.String()
}

func (st *autoState) skip(now time.Time, why string) {
	h := now.UTC().Format("2006-01-02T15")
	if st.Skipped[h] == nil {
		st.Skipped[h] = map[string]int{}
	}
	st.Skipped[h][why]++
}

func (st *autoState) waiting(trigger string) bool {
	for _, p := range st.Pending {
		if p.Trigger == trigger {
			return true
		}
	}
	return false
}

func (st *autoState) skippedSince(since time.Time) map[string]int {
	out := map[string]int{}
	for h, m := range st.Skipped {
		t, err := time.Parse("2006-01-02T15", h)
		if err != nil || t.Add(time.Hour).Before(since) {
			continue
		}
		for k, v := range m {
			out[k] += v
		}
	}
	return out
}

func (st *autoState) prune(now time.Time) {
	cut := now.Add(-autoKeep)
	var ds []autoSlot
	for _, d := range st.Dispatches {
		if !d.TS.Before(cut) {
			ds = append(ds, d)
		}
	}
	st.Dispatches = ds
	for h := range st.Skipped {
		if t, err := time.Parse("2006-01-02T15", h); err != nil || t.Before(cut) {
			delete(st.Skipped, h)
		}
	}
}

// readAutoState reads auto-incident.json (owner checked, no symlink); none
// yet is an empty state.
func readAutoState(dir string) (*autoState, error) {
	st := &autoState{V: 1, Skipped: map[string]map[string]int{}}
	b, err := detect.ReadStateFile(dir, autoIncidentFile, autoStateMax)
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("%s: %v", autoIncidentFile, err)
	}
	if st.Skipped == nil {
		st.Skipped = map[string]map[string]int{}
	}
	sort.SliceStable(st.Dispatches, func(i, j int) bool { return st.Dispatches[i].TS.Before(st.Dispatches[j].TS) })
	return st, nil
}

// withAutoState runs f on auto-incident.json under auto-incident.lock (the
// half-hourly patrol and the daily one are separate processes) and saves
// it atomically. A state that cannot be read is not reset: f does not run,
// so nothing is dispatched (fail closed).
func withAutoState(dir string, now time.Time, f func(*autoState)) error {
	lock, err := osutil.OpenNoFollow(filepath.Join(dir, autoIncidentLock), os.O_CREATE|os.O_RDWR, 0o600, false)
	if err != nil {
		return fmt.Errorf("%s: %v", autoIncidentLock, err)
	}
	defer lock.Close()
	for i := 0; ; i++ {
		err := osutil.TryLock(lock)
		if err == nil {
			break
		}
		if !errors.Is(err, osutil.ErrWouldBlock) || i+1 >= autoLockTries {
			return fmt.Errorf("%s: %v", autoIncidentLock, err)
		}
		time.Sleep(autoLockWait)
	}
	defer osutil.Unlock(lock)
	st, err := readAutoState(dir)
	if err != nil {
		return err
	}
	st.prune(now)
	f(st)
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, autoIncidentFile), b)
}
