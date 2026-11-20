package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nt-neil/shentu/internal/osutil"
	"github.com/nt-neil/shentu/tools"
)

// The dispatch archive (phase 2, A): one JSON line per dispatch in
// state_dir/dispatch/<YYYY-MM-DD>.jsonl, written before the report goes back
// to the commander. B (proposal buttons) and C (automatic incident
// dispatches) build on the types and functions below; their bodies are
// filled in by A.
//
// What a record holds is fixed: enumerations, counts and canonical IP
// addresses. No text a sub-agent or a log wrote (summaries, evidence,
// unchecked items, raw answers, tool output) is ever stored, so the archive
// cannot carry an injection or a secret into the daily report or a later
// turn. Whoever reads a record still treats it as untrusted.

const (
	dispatchDir     = "dispatch"          // under state_dir; 0700
	dispatchKeep    = 30 * 24 * time.Hour // like reports/attacks-<date>.txt
	dispatchVersion = 1                   // dispatchRecord.V
	buttonTTL       = 24 * time.Hour      // a proposal button can be pressed this long after its dispatch
	maxProposalSeq  = maxSubagents * 10   // proposals a record can hold
)

// Where a dispatch came from (dispatchRecord.Origin).
const (
	originChat     = "chat"          // shentu chat on the server
	originTelegram = "telegram"      // the bot
	originAuto     = "auto_incident" // C: an L3 alert, no one asked
)

// Outcome of a dispatch or of one sub-agent (Status).
const (
	statusComplete   = "complete"
	statusPartial    = "partial" // a dispatch: some sub-agents complete, some not
	statusIncomplete = "incomplete"
)

// Why a sub-agent ended as it did (subRecord.Reason). Never free text.
const (
	reasonOK         = "ok"
	reasonStepLimit  = "step_limit"
	reasonTokenCap   = "token_cap"
	reasonBudget     = "budget"
	reasonTimeout    = "timeout"
	reasonModelError = "model_error"
	reasonBadReport  = "bad_report"
	reasonSaidNot    = "said_incomplete" // the report itself said it did not finish
	reasonOther      = "other"           // none of the above (should not happen)
)

// A proposal's kind (proposalRecord.Action); only blocking for now.
const proposeBlockIP = "propose_block_ip"

// dispatchRecord is one line of the archive.
type dispatchRecord struct {
	V          int         `json:"v"`
	ID         string      `json:"id"` // the dispatch id (12 hex), as in log.jsonl's Dispatch
	TS         time.Time   `json:"ts"`
	Origin     string      `json:"origin"`            // originChat, originTelegram or originAuto
	Trigger    string      `json:"trigger,omitempty"` // originAuto: triggerID of the detector's group key, never the key itself
	Status     string      `json:"status"`            // statusComplete, statusPartial or statusIncomplete
	TokensUsed int         `json:"tokens_used"`
	TokensCap  int         `json:"tokens_cap"`
	Millis     int64       `json:"ms"`
	Subs       []subRecord `json:"subs"`
}

// subRecord is what one sub-agent did, in counts and enumerations.
type subRecord struct {
	Role         string           `json:"role"`   // a key of subRoles
	Status       string           `json:"status"` // statusComplete or statusIncomplete
	Reason       string           `json:"reason"` // a reason* constant
	Steps        int              `json:"steps"`
	ToolCalls    int              `json:"tool_calls"`
	TokensIn     int              `json:"tokens_in"`
	TokensOut    int              `json:"tokens_out"`
	TokensReason int              `json:"tokens_reason"`
	Findings     map[string]int   `json:"findings,omitempty"` // severity -> count
	Proposals    []proposalRecord `json:"proposals,omitempty"`
	Unchecked    int              `json:"unchecked"` // how many items it said it did not check
}

// proposalRecord is one proposed action. Seq is unique within the record
// (1, 2, ...), so a dispatch id and a seq name it: B's button carries only
// that pair (proposalRef), never the address. Loose is true when the
// sub-agent did not write the address in canonical form
// (hostenv.CanonicalIP of what it wrote differs from it): "::ffff:a.b.c.d"
// is stored as a.b.c.d but stays marked, and B offers no button for it.
type proposalRecord struct {
	Seq    int             `json:"seq"`
	Action string          `json:"action"` // proposeBlockIP
	IP     string          `json:"ip"`     // canonical form (net.IP.String()), checked by parseReport
	Loose  bool            `json:"loose"`  // what the sub-agent wrote was not IP itself
	Gate   tools.BlockCode `json:"gate"`   // tools.RemoteBlockCheck when the record was written; "" not checked
}

// proposalRef names one proposal: what a button's callback data carries.
type proposalRef struct {
	Dispatch string
	Seq      int
}

var (
	errNoRecord        = errors.New("no such dispatch in the archive")
	errNoProposal      = errors.New("no such proposal in that dispatch")
	errProposalExpired = errors.New("that proposal is older than its button may be")
	errArchive         = errors.New("the dispatch archive cannot be trusted") // wrong owner or mode, or not a regular file
)

var (
	dispatchIDRe = regexp.MustCompile(`^[0-9a-f]{12}$`)
	triggerRe    = regexp.MustCompile(`^t[0-9a-f]{16}$`)
	refRe        = regexp.MustCompile(`^d([0-9a-f]{12}):b([1-9][0-9]{0,2})$`)
	dayFileRe    = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2})\.jsonl$`)
	keptFileRe   = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2})\.jsonl(\.bad)?$`) // what prune ages out
)

// triggerID is what the archive stores for a trigger: a short hash of the
// detector's group key, which C compares with triggerID of a new alert's
// key. The key itself (it names a route) never reaches the archive.
func triggerID(key string) string {
	if key == "" {
		return ""
	}
	h := sha256.Sum256([]byte(key))
	return "t" + hex.EncodeToString(h[:8])
}

// String is the callback data form of ref: "d<dispatch>:b<seq>" (under
// Telegram's 64 bytes).
func (ref proposalRef) String() string {
	return "d" + ref.Dispatch + ":b" + strconv.Itoa(ref.Seq)
}

// parseProposalRef reads String's form back; anything else is an error
// (wrong prefix, an id that is not 12 hex, a seq outside 1..maxProposalSeq).
func parseProposalRef(s string) (proposalRef, error) {
	m := refRe.FindStringSubmatch(s)
	if m == nil {
		return proposalRef{}, errNoProposal
	}
	seq, err := strconv.Atoi(m[2])
	if err != nil || seq < 1 || seq > maxProposalSeq {
		return proposalRef{}, errNoProposal
	}
	return proposalRef{Dispatch: m[1], Seq: seq}, nil
}

// newDispatchRecord turns a finished dispatch into its record: statuses
// and reasons mapped to the enumerations, findings counted by severity,
// proposals numbered from 1 with their addresses in canonical form and
// Loose carried from parseReport. It leaves Gate unchecked; the caller
// fills it in with tools.RemoteBlockCheck before saving (A does not judge
// an address itself). trigger is the group key as the detector wrote it.
func newDispatchRecord(id, origin, trigger string, start time.Time, used, tokenCap int, reps []subReport) dispatchRecord {
	rec := dispatchRecord{V: dispatchVersion, ID: id, TS: start.UTC(), Origin: origin, Trigger: triggerID(trigger),
		TokensUsed: used, TokensCap: tokenCap, Millis: time.Since(start).Milliseconds(), Subs: []subRecord{}}
	done, seq := 0, 0
	for _, r := range reps {
		sr := subRecord{Role: r.Role, Status: statusIncomplete, Reason: r.code, Steps: r.steps, ToolCalls: r.toolCalls,
			TokensIn: r.tokIn, TokensOut: r.tokOut, TokensReason: r.tokReason, Unchecked: len(r.Unchecked)}
		if r.Status == statusComplete {
			sr.Status = statusComplete
			done++
		}
		if sr.Reason == "" {
			sr.Reason = reasonOther
			if sr.Status == statusComplete {
				sr.Reason = reasonOK
			}
		}
		for _, f := range r.Findings {
			if sr.Findings == nil {
				sr.Findings = map[string]int{}
			}
			sr.Findings[f.Severity]++
		}
		for _, p := range r.Proposals {
			ip := net.ParseIP(p.IP)
			if p.Action != proposeBlockIP || ip == nil || seq == maxProposalSeq {
				continue
			}
			seq++
			sr.Proposals = append(sr.Proposals, proposalRecord{Seq: seq, Action: proposeBlockIP, IP: ip.String(), Loose: p.Loose || p.IP != ip.String()})
		}
		rec.Subs = append(rec.Subs, sr)
	}
	switch {
	case len(reps) > 0 && done == len(reps):
		rec.Status = statusComplete
	case done > 0:
		rec.Status = statusPartial
	default:
		rec.Status = statusIncomplete
	}
	return rec
}

var (
	recOrigins  = map[string]bool{originChat: true, originTelegram: true, originAuto: true}
	recStatuses = map[string]bool{statusComplete: true, statusPartial: true, statusIncomplete: true}
	recReasons  = map[string]bool{reasonOK: true, reasonStepLimit: true, reasonTokenCap: true, reasonBudget: true, reasonTimeout: true,
		reasonModelError: true, reasonBadReport: true, reasonSaidNot: true, reasonOther: true}
	recGates = map[tools.BlockCode]bool{"": true, tools.BlockOK: true, tools.BlockUnverified: true, tools.BlockOverflow: true, tools.BlockWeak: true,
		tools.BlockInternal: true, tools.BlockLockout: true, tools.BlockNotCanonical: true, tools.BlockNoEvidence: true, tools.BlockStateError: true}
)

// check is the record's field checks: every word one of its enumeration,
// every address canonical, every number in range. Save and Since both use it.
func (rec *dispatchRecord) check() error {
	bad := func(what string) error { return fmt.Errorf("dispatch record: bad %s", what) }
	switch {
	case rec.V != dispatchVersion:
		return bad("version")
	case !dispatchIDRe.MatchString(rec.ID):
		return bad("id")
	case rec.TS.IsZero():
		return bad("time")
	case !recOrigins[rec.Origin]:
		return bad("origin")
	case rec.Trigger != "" && !triggerRe.MatchString(rec.Trigger):
		return bad("trigger")
	case !recStatuses[rec.Status]:
		return bad("status")
	case rec.TokensUsed < 0 || rec.TokensCap < 0 || rec.Millis < 0:
		return bad("count")
	case len(rec.Subs) > maxSubagents:
		return bad("sub-agent count")
	}
	seen := map[int]bool{}
	for _, s := range rec.Subs {
		if _, ok := subRoles[s.Role]; !ok {
			return bad("role")
		}
		if s.Status != statusComplete && s.Status != statusIncomplete {
			return bad("sub-agent status")
		}
		if !recReasons[s.Reason] {
			return bad("reason")
		}
		if s.Steps < 0 || s.ToolCalls < 0 || s.TokensIn < 0 || s.TokensOut < 0 || s.TokensReason < 0 || s.Unchecked < 0 {
			return bad("count")
		}
		for sev, n := range s.Findings {
			if (!severities[sev] && sev != "unknown") || n < 0 {
				return bad("finding")
			}
		}
		for _, p := range s.Proposals {
			ip := net.ParseIP(p.IP)
			if p.Seq < 1 || p.Seq > maxProposalSeq || seen[p.Seq] || p.Action != proposeBlockIP || ip == nil || ip.String() != p.IP || !recGates[p.Gate] {
				return bad("proposal")
			}
			seen[p.Seq] = true
		}
	}
	return nil
}

// dispatchStore is the archive under one state_dir.
type dispatchStore struct {
	dir string // state_dir/dispatch
	now func() time.Time
}

// newDispatchStore is the archive of cfg's state_dir. It creates nothing
// until the first Save.
func newDispatchStore(cfg *Config) *dispatchStore {
	return &dispatchStore{dir: filepath.Join(cfg.StateDir, dispatchDir), now: time.Now}
}

// trusted says whether st, a file or the directory of the archive, can be
// believed: not a link, this process's user's, and nobody else may read,
// write or (for the directory) list it.
func trusted(st os.FileInfo, dir bool) bool {
	mode := st.Mode()
	if mode&os.ModeSymlink != 0 || !ownDir(st) {
		return false
	}
	if runtime.GOOS == "windows" { // modes there say nothing of who may read; the state dir's ACL does
		return mode.IsDir() == dir && (dir || mode.IsRegular())
	}
	if dir {
		return mode.IsDir() && mode.Perm()&0o077 == 0
	}
	return mode.IsRegular() && mode.Perm()&0o077 == 0
}

// Save appends rec to its day's file (0600, in a 0700 directory, both this
// process's user's, the file opened without following a link), after
// checking every field; a record that fails is refused. The line goes out in
// one write, after a newline when the file does not end in one (a write cut
// short before), so a broken line never takes the next record with it. It
// also removes files older than dispatchKeep.
func (s *dispatchStore) Save(rec dispatchRecord) error {
	if !filepath.IsAbs(s.dir) {
		return fmt.Errorf("%w: state_dir is not an absolute path", errArchive)
	}
	if err := rec.check(); err != nil {
		return err
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	if st, err := os.Lstat(s.dir); err != nil || !trusted(st, true) {
		return fmt.Errorf("%w: %s", errArchive, s.dir)
	}
	p := filepath.Join(s.dir, rec.TS.Local().Format(time.DateOnly)+".jsonl")
	f, st, err := openDayLocked(p, os.O_RDWR|os.O_APPEND|os.O_CREATE)
	if err != nil {
		return err
	}
	defer f.Close()
	line := append(b, '\n')
	if st.Size() > 0 {
		last := make([]byte, 1)
		if _, err := f.ReadAt(last, st.Size()-1); err != nil {
			return err
		}
		if last[0] != '\n' {
			line = append([]byte{'\n'}, line...)
		}
	}
	if _, err := f.Write(line); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	s.prune()
	return nil
}

// prune removes day files older than dispatchKeep, and the lines Repair
// moved aside with them. Save and Since both run it, so a host that stops
// dispatching still drops old files on its daily report.
func (s *dispatchStore) prune() {
	ents, _ := os.ReadDir(s.dir)
	for _, e := range ents {
		m := keptFileRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		if d, err := time.ParseInLocation(time.DateOnly, m[1], time.Local); err == nil && s.now().Sub(d) > dispatchKeep+24*time.Hour {
			os.Remove(filepath.Join(s.dir, e.Name()))
		}
	}
}

// Since returns the records written at or after t, oldest first. A file
// not this process's user's, readable or writable by anyone else, or not a
// regular file makes it fail with errArchive; a line that does not parse
// or fails the field checks is skipped and counted in bad. No archive yet
// is no records.
func (s *dispatchStore) Since(t time.Time) (recs []dispatchRecord, bad int, err error) {
	if !filepath.IsAbs(s.dir) {
		return nil, 0, fmt.Errorf("%w: state_dir is not an absolute path", errArchive)
	}
	st, err := os.Lstat(s.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil || !trusted(st, true) {
		return nil, 0, fmt.Errorf("%w: %s", errArchive, s.dir)
	}
	s.prune()
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, 0, err
	}
	from := t.Local().Add(-24 * time.Hour).Format(time.DateOnly) // a day's file starts at local midnight
	for _, e := range ents {
		m := dayFileRe.FindStringSubmatch(e.Name())
		if m == nil || m[1] < from {
			continue
		}
		p := filepath.Join(s.dir, e.Name())
		b, err := readTrusted(p)
		if err != nil {
			return nil, 0, err
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			var rec dispatchRecord
			dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
			dec.DisallowUnknownFields()
			if dec.Decode(&rec) != nil || rec.check() != nil {
				bad++
				continue
			}
			if !rec.TS.Before(t) {
				recs = append(recs, rec)
			}
		}
		if sc.Err() != nil {
			bad++
		}
	}
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].TS.Before(recs[j].TS) })
	return recs, bad, nil
}

// readTrusted reads p, opened without following a link, when it is a file
// trusted can believe.
func readTrusted(p string) ([]byte, error) {
	f, err := osutil.OpenNoFollow(p, os.O_RDONLY, 0, true)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", errArchive, p, err)
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !trusted(st, false) {
		return nil, fmt.Errorf("%w: %s", errArchive, p)
	}
	return io.ReadAll(f)
}

// Get returns the record with this dispatch id from the last dispatchKeep.
func (s *dispatchStore) Get(id string) (dispatchRecord, error) {
	if !dispatchIDRe.MatchString(id) {
		return dispatchRecord{}, errNoRecord
	}
	recs, _, err := s.Since(s.now().Add(-dispatchKeep))
	if err != nil {
		return dispatchRecord{}, err
	}
	for i := len(recs) - 1; i >= 0; i-- {
		if recs[i].ID == id {
			return recs[i], nil
		}
	}
	return dispatchRecord{}, errNoRecord
}

// Proposal looks a proposal up by its ref, for B's button press; one older
// than buttonTTL is errProposalExpired. What it returns is only what was
// proposed: the press still runs RemoteRefused, Preview, blockGate
// (remoteGate from Telegram) and the button confirmation from the start.
func (s *dispatchStore) Proposal(ref proposalRef) (dispatchRecord, proposalRecord, error) {
	rec, err := s.Get(ref.Dispatch)
	if err != nil {
		return dispatchRecord{}, proposalRecord{}, err
	}
	if s.now().Sub(rec.TS) > buttonTTL {
		return dispatchRecord{}, proposalRecord{}, errProposalExpired
	}
	for _, sr := range rec.Subs {
		for _, p := range sr.Proposals {
			if p.Seq == ref.Seq {
				return rec, p, nil
			}
		}
	}
	return dispatchRecord{}, proposalRecord{}, errNoProposal
}

// AutoSince counts the automatic dispatches (originAuto) at or after t and
// the triggers (triggerID) they were for, for C's daily cap and its
// once-per-group rule. A line it cannot read could be one of them, so any
// makes it an error: C then does not dispatch (fail closed).
func (s *dispatchStore) AutoSince(t time.Time) (n int, triggers map[string]bool, err error) {
	recs, bad, err := s.Since(t)
	if err != nil {
		return 0, nil, err
	}
	if bad > 0 {
		return 0, nil, fmt.Errorf("%w: %d lines could not be read", errArchive, bad)
	}
	triggers = map[string]bool{}
	for _, r := range recs {
		if r.Origin == originAuto {
			n++
			if r.Trigger != "" {
				triggers[r.Trigger] = true
			}
		}
	}
	return n, triggers, nil
}

// maskNet is ip's network for a report: /24, or /64 for IPv6.
func maskNet(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return "?"
	}
	if v4 := ip.To4(); v4 != nil {
		return (&net.IPNet{IP: v4.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}).String()
	}
	return (&net.IPNet{IP: ip.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)}).String()
}

// countLine is "a 2, b 1" in the order of keys.
func countLine(c map[string]int) string {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, c[k]))
	}
	return strings.Join(parts, ", ")
}

const maxReportProposals = 10

// dispatchSection is the daily report's lines about the last day's
// dispatches: counts by origin, role and status, reasons, and proposals
// with their addresses masked to /24 (/64 for IPv6), like the attack
// report. Only enumerations and numbers reach it. An archive error is said,
// not hidden; no dispatches and no error give "".
func dispatchSection(recs []dispatchRecord, bad int, err error) string {
	if err != nil {
		return "\nSub-agent dispatches: the archive could not be read (" + err.Error() + ")\n"
	}
	if len(recs) == 0 && bad == 0 {
		return ""
	}
	origins, statuses, roles, reasons := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	var props []string
	more := 0
	for _, r := range recs {
		origins[r.Origin]++
		statuses[r.Status]++
		for _, s := range r.Subs {
			roles[s.Role+" "+s.Status]++
			if s.Status != statusComplete {
				reasons[s.Reason]++
			}
			for _, p := range s.Proposals {
				if len(props) == maxReportProposals {
					more++
					continue
				}
				props = append(props, fmt.Sprintf("%s (gate %s)", maskNet(p.IP), cmpOr(string(p.Gate), "not checked")))
			}
		}
	}
	var b strings.Builder
	b.WriteString("\nSub-agent dispatches (last day; reports are the model's, not verified):\n")
	fmt.Fprintf(&b, "- %d dispatches: %s; %s\n", len(recs), countLine(origins), countLine(statuses))
	if len(roles) > 0 {
		fmt.Fprintf(&b, "- sub-agents: %s\n", countLine(roles))
	}
	if len(reasons) > 0 {
		fmt.Fprintf(&b, "- why incomplete: %s\n", countLine(reasons))
	}
	if len(props) > 0 {
		fmt.Fprintf(&b, "- proposed blocks (suggestions, not actions): %s", strings.Join(props, ", "))
		if more > 0 {
			fmt.Fprintf(&b, ", and %d more", more)
		}
		b.WriteString("\n")
	}
	if bad > 0 {
		fmt.Fprintf(&b, "- %d archive lines could not be read and were skipped\n", bad)
	}
	return b.String()
}

func cmpOr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// dispatchDaily is dispatchSection for the day before now, for the daily report.
func dispatchDaily(cfg *Config, now time.Time) string {
	s := newDispatchStore(cfg)
	recs, bad, err := s.Since(now.Add(-24 * time.Hour))
	sec := dispatchSection(recs, bad, err)
	if line := s.repairedLine(now); line != "" {
		if sec == "" {
			sec = "\nSub-agent dispatches (last day; reports are the model's, not verified):\n"
		}
		sec += line
	}
	return sec
}

// runDispatch runs tasks one after another as sub-agents of a, then saves
// the dispatch's record (with each proposal's tools.RemoteBlockCheck code)
// before anyone reads the reports. (*agent).dispatch and C's automatic
// incident dispatch both use it; trigger is the detector's group key for
// originAuto, "" otherwise. rec is the record as saved (or as it would have
// been); saveErr says it was not. An archive that cannot be written is also
// logged, never a reason to drop the reports.
func (a *agent) runDispatch(ctx context.Context, origin, trigger string, tasks []subTask) (id string, reports []subReport, rec dispatchRecord, saveErr error) {
	idb := make([]byte, 6)
	rand.Read(idb)
	id = hex.EncodeToString(idb)
	a.lastDispatch = id // from now on, any control call in this agent is treated as coming from a sub-agent's report
	start := time.Now()

	dctx, cancel := context.WithTimeout(ctx, dispatchTimeout)
	defer cancel()
	left := dispatchTokenCap
	for _, t := range tasks {
		if dctx.Err() != nil || left <= 0 {
			why, code := "the dispatch time limit was reached before this sub-agent started", reasonTimeout
			if left <= 0 {
				why, code = "the dispatch token limit was reached before this sub-agent started", reasonTokenCap
			}
			reports = append(reports, subReport{Role: t.Role, Status: "incomplete", Reason: why, Findings: []subFinding{}, code: code})
			continue
		}
		rep := a.runSub(dctx, id, t, min(subTokenCap, left))
		left -= rep.Tokens
		reports = append(reports, rep)
	}

	rec = newDispatchRecord(id, origin, trigger, start, dispatchTokenCap-left, dispatchTokenCap, reports)
	gctx, gcancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer gcancel()
	for i := range rec.Subs {
		for j := range rec.Subs[i].Proposals {
			p := &rec.Subs[i].Proposals[j]
			_, code, _ := tools.RemoteBlockCheck(gctx, a.env, net.ParseIP(p.IP))
			if !recGates[code] || code == "" {
				code = tools.BlockStateError
			}
			p.Gate = code
		}
	}
	if saveErr = newDispatchStore(a.cfg).Save(rec); saveErr != nil {
		a.log.write(logEntry{Actor: a.actor, Tool: "dispatch", Dispatch: id, Error: mask("archive: " + saveErr.Error())})
	}
	return id, reports, rec, saveErr
}

// dispatchOrigin is where a's dispatches come from: the bot's agents have
// Remote set, the server's chat does not.
func (a *agent) dispatchOrigin() string {
	if a.env != nil && a.env.Remote {
		return originTelegram
	}
	return originChat
}

// Repair moves every line of the archive's day files that Since cannot
// read (cut short by a full disk, say) to <date>.jsonl.bad next to it
// (0600), drops empty lines (they are no record, but Since counts them
// unreadable), and keeps the others as they were, so the automatic
// incident checks need not wait for the file to age out. It takes each
// file's lock, as Save does, refuses an archive Since would not read, and
// notes what it did in repairs.jsonl for the daily report.
func (s *dispatchStore) Repair() (moved, dropped int, err error) {
	if !filepath.IsAbs(s.dir) {
		return 0, 0, fmt.Errorf("%w: state_dir is not an absolute path", errArchive)
	}
	st, err := os.Lstat(s.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, 0, nil
	}
	if err != nil || !trusted(st, true) {
		return 0, 0, fmt.Errorf("%w: %s", errArchive, s.dir)
	}
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, 0, err
	}
	for _, e := range ents {
		if !dayFileRe.MatchString(e.Name()) {
			continue
		}
		m, d, err := s.repairFile(filepath.Join(s.dir, e.Name()))
		moved, dropped = moved+m, dropped+d
		if err != nil {
			s.noteRepair(moved, dropped)
			return moved, dropped, err
		}
	}
	return moved, dropped, s.noteRepair(moved, dropped)
}

// repairNote is one line of repairs.jsonl: what one Repair did.
type repairNote struct {
	TS      time.Time `json:"ts"`
	Moved   int       `json:"moved"`
	Dropped int       `json:"dropped"`
}

const repairsFile = "repairs.jsonl"

// noteRepair adds what a Repair did to repairs.jsonl, keeping dispatchKeep.
func (s *dispatchStore) noteRepair(moved, dropped int) error {
	if moved == 0 && dropped == 0 {
		return nil
	}
	notes := s.repairNotes(s.now().Add(-dispatchKeep))
	notes = append(notes, repairNote{TS: s.now().UTC(), Moved: moved, Dropped: dropped})
	var b bytes.Buffer
	for _, n := range notes {
		line, _ := json.Marshal(n)
		b.Write(append(line, '\n'))
	}
	p := filepath.Join(s.dir, repairsFile)
	if st, err := os.Lstat(p); err == nil && !trusted(st, false) {
		return fmt.Errorf("%w: %s", errArchive, p)
	}
	return replaceFile(p, b.Bytes())
}

// repairNotes are the notes at or after t; an unreadable file or line is none.
func (s *dispatchStore) repairNotes(t time.Time) []repairNote {
	b, err := readTrusted(filepath.Join(s.dir, repairsFile))
	if err != nil {
		return nil
	}
	var notes []repairNote
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		var n repairNote
		if json.Unmarshal(line, &n) == nil && !n.TS.Before(t) && n.Moved >= 0 && n.Dropped >= 0 {
			notes = append(notes, n)
		}
	}
	return notes
}

func (s *dispatchStore) repairFile(p string) (moved, dropped int, err error) {
	f, _, err := openDayLocked(p, os.O_RDONLY)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		return 0, 0, err
	}
	var good, bad bytes.Buffer
	lines := bytes.Split(b, []byte{'\n'})
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1] // what follows the last newline
	}
	for _, line := range lines {
		if len(line) == 0 { // not a record: Since counts it unreadable, Repair drops it
			dropped++
			continue
		}
		var rec dispatchRecord
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if len(line) <= 1<<20 && dec.Decode(&rec) == nil && rec.check() == nil { // as Since reads it
			good.Write(line)
			good.WriteByte('\n')
			continue
		}
		bad.Write(line)
		bad.WriteByte('\n')
		moved++
	}
	if moved == 0 && dropped == 0 {
		return 0, 0, nil
	}
	if moved > 0 {
		if err := appendBad(p+".bad", bad.Bytes()); err != nil {
			return 0, 0, err
		}
	}
	// The kept lines replace the file in one rename: a write that fails
	// (a full disk is why Repair runs) leaves the file as it was.
	if err := replaceFile(p, good.Bytes()); err != nil {
		return 0, 0, err
	}
	return moved, dropped, nil
}

// openDayLocked opens a day file without following a link, takes its lock
// and checks it, and opens it again if Repair replaced it meanwhile (the
// lock was then on the old file).
func openDayLocked(p string, flag int) (*os.File, os.FileInfo, error) {
	for range 3 {
		f, err := osutil.OpenNoFollow(p, flag, 0o600, true)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %s: %v", errArchive, p, err)
		}
		if err := osutil.Lock(f); err != nil {
			f.Close()
			return nil, nil, err
		}
		st, err := f.Stat()
		if err != nil || !trusted(st, false) {
			f.Close()
			return nil, nil, fmt.Errorf("%w: %s", errArchive, p)
		}
		if now, err := os.Lstat(p); err == nil && os.SameFile(st, now) {
			return f, st, nil
		}
		f.Close()
	}
	return nil, nil, fmt.Errorf("%w: %s keeps changing", errArchive, p)
}

// appendBad appends lines to a .bad file, unless it already ends with them
// (a Repair that stopped after this step and runs again).
func appendBad(p string, lines []byte) error {
	bf, err := osutil.OpenNoFollow(p, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600, true)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", errArchive, p, err)
	}
	defer bf.Close()
	st, err := bf.Stat()
	if err != nil || !trusted(st, false) {
		return fmt.Errorf("%w: %s", errArchive, p)
	}
	if st.Size() >= int64(len(lines)) {
		tail := make([]byte, len(lines))
		if _, err := bf.ReadAt(tail, st.Size()-int64(len(lines))); err == nil && bytes.Equal(tail, lines) {
			return nil
		}
	}
	if _, err := bf.Write(lines); err != nil {
		return err
	}
	return bf.Sync() // the moved lines are kept before they leave the day file
}

// replaceWrite writes a temporary file; tests swap it to fail midway.
var replaceWrite = func(f *os.File, b []byte) error {
	_, err := f.Write(b)
	return err
}

// replaceFile puts b in place of p: a temporary file in the same directory
// (0600), synced, then renamed over p, so p is either all old or all new.
func replaceFile(p string, b []byte) error {
	tf, err := os.CreateTemp(filepath.Dir(p), "."+filepath.Base(p)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := tf.Name()
	werr := replaceWrite(tf, b)
	serr := tf.Sync()
	cerr := tf.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return err
	}
	if d, err := os.Open(filepath.Dir(p)); err == nil { // the rename itself, on disk
		d.Sync()
		d.Close()
	}
	return nil
}

// repairedLine is the daily report's line about what Repair did in the
// last day; "" when it did nothing.
func (s *dispatchStore) repairedLine(now time.Time) string {
	moved, dropped, runs := 0, 0, 0
	for _, n := range s.repairNotes(now.Add(-24 * time.Hour)) {
		moved, dropped, runs = moved+n.Moved, dropped+n.Dropped, runs+1
	}
	if runs == 0 {
		return ""
	}
	return fmt.Sprintf("- `shentu dispatch repair` ran %d times: %d unreadable archive lines moved to *.jsonl.bad, %d empty lines dropped (%s)\n", runs, moved, dropped, s.dir)
}

// dispatchCommand is `shentu dispatch repair`.
func dispatchCommand(cfg *Config, args []string, root bool) error {
	if len(args) != 1 || args[0] != "repair" {
		return errors.New("usage: shentu dispatch repair")
	}
	if !root {
		return errors.New("shentu dispatch repair changes the dispatch archive: run it as root (sudo shentu dispatch repair)")
	}
	n, d, err := newDispatchStore(cfg).Repair()
	if err != nil {
		return err
	}
	if n == 0 && d == 0 {
		fmt.Println("shentu dispatch repair: every line of the dispatch archive can be read; nothing moved.")
		return nil
	}
	fmt.Printf("shentu dispatch repair: moved %d unreadable lines to *.jsonl.bad and dropped %d empty lines in %s; automatic incident checks count again from the next patrol.\n", n, d, filepath.Join(cfg.StateDir, dispatchDir))
	return nil
}
