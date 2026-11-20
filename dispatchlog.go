package main

import (
	"errors"
	"time"

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
)

// A proposal's kind (proposalRecord.Action); only blocking for now.
const proposeBlockIP = "propose_block_ip"

// dispatchRecord is one line of the archive.
type dispatchRecord struct {
	V          int         `json:"v"`
	ID         string      `json:"id"` // the dispatch id (12 hex), as in log.jsonl's Dispatch
	TS         time.Time   `json:"ts"`
	Origin     string      `json:"origin"`            // originChat, originTelegram or originAuto
	Trigger    string      `json:"trigger,omitempty"` // originAuto: the detector's group key (detect.Group.Key), checked against a pattern
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
	errNoRecord   = errors.New("no such dispatch in the archive")
	errNoProposal = errors.New("no such proposal in that dispatch")
	errArchive    = errors.New("the dispatch archive cannot be trusted") // wrong owner or mode, or not a regular file
)

// String is the callback data form of ref: "d<dispatch>:b<seq>" (under
// Telegram's 64 bytes).
// TODO(A): implement; B uses it for the button.
func (ref proposalRef) String() string {
	return ""
}

// parseProposalRef reads String's form back; anything else is an error
// (wrong prefix, an id that is not 12 hex, a seq outside 1..maxProposalSeq).
// TODO(A): implement; B uses it on a button press.
func parseProposalRef(s string) (proposalRef, error) {
	return proposalRef{}, errors.New("not implemented")
}

// newDispatchRecord turns a finished dispatch into its record: statuses
// and reasons mapped to the enumerations, findings counted by severity,
// proposals numbered from 1 with their addresses in canonical form. It
// leaves Gate unchecked; the caller fills it in with tools.RemoteBlockCheck
// before saving (A does not judge an address itself). Loose is set here.
// TODO(A): implement, and call it from (*agent).dispatch.
func newDispatchRecord(id, origin, trigger string, start time.Time, used, tokenCap int, reps []subReport, subs []subRecord) dispatchRecord {
	return dispatchRecord{}
}

// dispatchStore is the archive under one state_dir.
type dispatchStore struct {
	dir string // state_dir/dispatch
}

// newDispatchStore is the archive of cfg's state_dir. It creates nothing
// until the first Save.
func newDispatchStore(cfg *Config) *dispatchStore {
	return &dispatchStore{}
}

// Save appends rec to the day's file (0600, in a 0700 directory, both
// root's), after checking every field against its enumeration or pattern;
// a record that fails is refused, never written in part. It also removes
// files older than dispatchKeep.
// TODO(A): implement.
func (s *dispatchStore) Save(rec dispatchRecord) error {
	return errors.New("not implemented")
}

// Since returns the records written at or after t, oldest first. A file
// not owned by root, writable by anyone else or not a regular file makes it
// fail with errArchive; a line that does not parse or fails the field
// checks is skipped and counted in bad.
// TODO(A): implement.
func (s *dispatchStore) Since(t time.Time) (recs []dispatchRecord, bad int, err error) {
	return nil, 0, errors.New("not implemented")
}

// Get returns the record with this dispatch id from the last dispatchKeep.
// TODO(A): implement.
func (s *dispatchStore) Get(id string) (dispatchRecord, error) {
	return dispatchRecord{}, errNoRecord
}

// Proposal looks a proposal up by its ref, for B's button press. What it
// returns is only what was proposed: the press still runs RemoteRefused,
// Preview, blockGate (remoteGate from Telegram) and the button confirmation
// from the start.
// TODO(A): implement on top of Get.
func (s *dispatchStore) Proposal(ref proposalRef) (dispatchRecord, proposalRecord, error) {
	return dispatchRecord{}, proposalRecord{}, errNoProposal
}

// AutoSince counts the automatic dispatches (originAuto) at or after t and
// the triggers they were for, for C's daily cap and its once-per-group rule.
// TODO(A): implement on top of Since.
func (s *dispatchStore) AutoSince(t time.Time) (n int, triggers map[string]bool, err error) {
	return 0, nil, errors.New("not implemented")
}

// dispatchSection is the daily report's lines about the last day's
// dispatches: counts by origin, role and status, reasons, and proposals
// with their addresses masked to /24 (/64 for IPv6), like the attack
// report. Only enumerations and numbers reach it. An archive error is said,
// not hidden; no dispatches and no error give "".
// TODO(A): implement, and add it to the daily report next to detectSection.
func dispatchSection(recs []dispatchRecord, bad int, err error) string {
	return ""
}
