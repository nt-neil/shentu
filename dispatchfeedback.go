package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Operator feedback on sub-agent reports (phase 3, G): two buttons under a
// dispatch's report, "useful" and "false positive", for the paired user,
// each set once, within feedbackTTL. A press is a fixed word in
// dispatch/feedback.jsonl, nothing else. `shentu dispatch stats` adds the
// archive and the feedback up by role, in numbers, and suggests changes
// within fixed ranges for a person to review: Shentu never applies one
// itself, and a tool can only be suggested away, never added.

const (
	feedbackTTL          = 7 * 24 * time.Hour
	feedbackFile         = "feedback.jsonl"
	verdictUseful        = "useful"
	verdictFalsePos      = "false_positive"
	statsMinRuns         = 5   // a role's suggestions need this many runs
	statsMinFeedback     = 5   // and its prompt review this many verdicts
	statsShare           = 0.3 // the share of runs stopped for one reason that suggests more room
	statsFalseShare      = 0.5 // the share of false positives that suggests a prompt review
	stepsMin, stepsMax   = 4, 10
	tokensMin, tokensMax = 20_000, 60_000
)

// feedbackSet is the feedback buttons offered under one dispatch, in bot.json.
type feedbackSet struct {
	Pair string    `json:"pair"`
	At   time.Time `json:"at"` // when they were offered: they expire feedbackTTL after
	Used bool      `json:"used,omitempty"`
}

// feedbackRef is a feedback button's callback data: "d<dispatch>:f<u|p>".
type feedbackRef struct {
	Dispatch string
	Verdict  string
}

var feedbackRe = regexp.MustCompile(`^d([0-9a-f]{12}):f([up])$`)

func (r feedbackRef) String() string {
	v := "u"
	if r.Verdict == verdictFalsePos {
		v = "p"
	}
	return "d" + r.Dispatch + ":f" + v
}

func parseFeedbackRef(s string) (feedbackRef, error) {
	m := feedbackRe.FindStringSubmatch(s)
	if m == nil {
		return feedbackRef{}, errors.New("not a feedback button")
	}
	v := verdictUseful
	if m[2] == "p" {
		v = verdictFalsePos
	}
	return feedbackRef{Dispatch: m[1], Verdict: v}, nil
}

// feedbackLine is one line of feedback.jsonl.
type feedbackLine struct {
	ID      string    `json:"id"`
	Verdict string    `json:"verdict"`
	TS      time.Time `json:"ts"`
}

func (f feedbackLine) ok() bool {
	return dispatchIDRe.MatchString(f.ID) && (f.Verdict == verdictUseful || f.Verdict == verdictFalsePos) && !f.TS.IsZero()
}

// SaveFeedback appends a verdict on dispatch id, which must be in the archive.
func (s *dispatchStore) SaveFeedback(id, verdict string, now time.Time) error {
	l := feedbackLine{ID: id, Verdict: verdict, TS: now.UTC()}
	if !l.ok() {
		return errors.New("feedback: bad id or verdict")
	}
	if _, err := s.Get(id); err != nil {
		return err
	}
	b, _ := json.Marshal(l)
	p := filepath.Join(s.dir, feedbackFile)
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	f, _, err := openChecked(p, os.O_RDWR|os.O_APPEND|os.O_CREATE)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Close()
}

// Feedback is the latest verdict on each dispatch given at or after t; a
// line that does not check out is skipped and counted in bad.
func (s *dispatchStore) Feedback(t time.Time) (map[string]string, int, error) {
	p := filepath.Join(s.dir, feedbackFile)
	if _, err := os.Lstat(p); errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, 0, nil
	}
	b, err := readTrusted(p)
	if err != nil {
		return nil, 0, err
	}
	out, bad := map[string]string{}, 0
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var l feedbackLine
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if dec.Decode(&l) != nil || !l.ok() {
			bad++
			continue
		}
		if !l.TS.Before(t) {
			out[l.ID] = l.Verdict
		}
	}
	return out, bad, nil
}

// offerFeedback sends the two feedback buttons under dispatch id's report.
func (b *bot) offerFeedback(ctx context.Context, chat int64, id, owner, origin string) {
	if b.archive == nil || id == "" {
		return
	}
	rec, err := b.archive.Get(id)
	if err != nil || rec.Origin != origin {
		return
	}
	ok := false
	err = withBotState(b.cfg.StateDir, func(s *botState) error {
		if pairKey(*s) != owner || s.Paused != "" {
			return nil
		}
		for k, v := range s.Feedback {
			if time.Since(v.At) > feedbackTTL {
				delete(s.Feedback, k)
			}
		}
		if s.Feedback == nil {
			s.Feedback = map[string]*feedbackSet{}
		}
		s.Feedback[id] = &feedbackSet{Pair: owner, At: time.Now().UTC()}
		ok = true
		return nil
	})
	if err != nil || !ok {
		return // a button bot.json does not hold could not be checked when pressed
	}
	kb := map[string]any{"inline_keyboard": [][]map[string]string{{
		{"text": b.t("fb_useful"), "callback_data": feedbackRef{id, verdictUseful}.String()},
		{"text": b.t("fb_false"), "callback_data": feedbackRef{id, verdictFalsePos}.String()},
	}}}
	b.send(ctx, chat, fmt.Sprintf(b.t("fb_ask"), id), kb)
}

// pressFeedback handles a press of a feedback button by the paired user:
// the button must have been offered to this pairing, within feedbackTTL,
// and not used; the dispatch must be in the archive. Then the verdict is
// saved, once.
func (b *bot) pressFeedback(ctx context.Context, st botState, ref feedbackRef) {
	entry := logEntry{Actor: "bot", Tool: "dispatch_feedback", Dispatch: ref.Dispatch, Args: ref.Verdict}
	why := "no such button"
	err := withBotState(b.cfg.StateDir, func(s *botState) error {
		set := s.Feedback[ref.Dispatch]
		switch {
		case set == nil:
		case set.Pair != pairKey(st) || pairKey(*s) != pairKey(st):
			why = "the button was offered to another pairing"
		case time.Since(set.At) > feedbackTTL:
			why = "the button expired"
		case set.Used:
			why = "the button was already pressed"
		default:
			set.Used, why = true, ""
		}
		return nil
	})
	if err == nil && why == "" && b.archive != nil {
		err = newDispatchStore(b.cfg).SaveFeedback(ref.Dispatch, ref.Verdict, time.Now())
	} else if err == nil && why == "" {
		why = "no archive"
	}
	switch {
	case err != nil:
		entry.Error = "feedback not saved: " + mask(err.Error())
	case why != "":
		entry.Error = why
	default:
		entry.OK = true
	}
	b.log.write(entry)
	if entry.OK {
		b.send(ctx, st.ChatID, b.t("fb_thanks"), nil)
	} else {
		b.send(ctx, st.ChatID, b.t("prop_gone"), nil)
	}
}

// roleStats is one role's numbers over the dispatches added up.
type roleStats struct {
	Role      string         `json:"role"`
	Runs      int            `json:"runs"`
	Complete  int            `json:"complete"`
	Reasons   map[string]int `json:"reasons"` // why runs were incomplete
	Steps     int            `json:"steps"`   // in all runs
	Tokens    int            `json:"tokens"`
	Proposals int            `json:"proposals"`
	Refused   int            `json:"refused"` // proposals the gate refused
	Useful    int            `json:"useful"`  // verdicts on dispatches this role was in
	FalsePos  int            `json:"false_positive"`
}

// suggestion is one change for a person to review. Kind is steps, tokens,
// review_prompt or remove_tool; To is the new value for steps and tokens.
type suggestion struct {
	Role string `json:"role"`
	Kind string `json:"kind"`
	From int    `json:"from,omitempty"`
	To   int    `json:"to,omitempty"`
	Tool string `json:"tool,omitempty"`
	Why  string `json:"why"`
}

// dispatchStats adds records and verdicts up by role: from fixed words and
// numbers only.
func dispatchStats(recs []dispatchRecord, verdicts map[string]string) []*roleStats {
	by := map[string]*roleStats{}
	for _, r := range recs {
		for _, s := range r.Subs {
			st := by[s.Role]
			if st == nil {
				st = &roleStats{Role: s.Role, Reasons: map[string]int{}}
				by[s.Role] = st
			}
			st.Runs++
			if s.Status == statusComplete {
				st.Complete++
			} else {
				st.Reasons[s.Reason]++
			}
			st.Steps += s.Steps
			st.Tokens += s.TokensIn + s.TokensOut + s.TokensReason
			for _, p := range s.Proposals {
				st.Proposals++
				if p.Gate != "" && p.Gate != "ok" {
					st.Refused++
				}
			}
			switch verdicts[r.ID] {
			case verdictUseful:
				st.Useful++
			case verdictFalsePos:
				st.FalsePos++
			}
		}
	}
	out := make([]*roleStats, 0, len(by))
	for _, r := range subRoleOrder {
		if by[r] != nil {
			out = append(out, by[r])
		}
	}
	return out
}

// suggest turns the numbers into suggestions, each checked by checkSuggestion.
func suggest(stats []*roleStats) []suggestion {
	var out []suggestion
	add := func(s suggestion) {
		if checkSuggestion(s) == nil {
			out = append(out, s)
		}
	}
	for _, st := range stats {
		if st.Runs < statsMinRuns {
			continue
		}
		share := func(reason string) float64 { return float64(st.Reasons[reason]) / float64(st.Runs) }
		if share(reasonStepLimit) >= statsShare && subMaxSteps < stepsMax {
			add(suggestion{Role: st.Role, Kind: "steps", From: subMaxSteps, To: min(subMaxSteps+2, stepsMax),
				Why: fmt.Sprintf("%d of %d runs used up their steps", st.Reasons[reasonStepLimit], st.Runs)})
		}
		if share(reasonTokenCap) >= statsShare && subTokenCap < tokensMax {
			add(suggestion{Role: st.Role, Kind: "tokens", From: subTokenCap, To: min(subTokenCap+10_000, tokensMax),
				Why: fmt.Sprintf("%d of %d runs reached their token limit", st.Reasons[reasonTokenCap], st.Runs)})
		}
		if n := st.Useful + st.FalsePos; n >= statsMinFeedback && float64(st.FalsePos)/float64(n) >= statsFalseShare {
			add(suggestion{Role: st.Role, Kind: "review_prompt",
				Why: fmt.Sprintf("%d of %d verdicts on its dispatches were false positives", st.FalsePos, n)})
		}
	}
	return out
}

// checkSuggestion keeps a suggestion within what may change: a known role,
// steps and tokens within their ranges, a tool only removed from a role
// that has it (never a control tool, never its last), nothing else.
func checkSuggestion(s suggestion) error {
	r, ok := subRoles[s.Role]
	if !ok {
		return errors.New("suggestion: unknown role")
	}
	switch s.Kind {
	case "steps":
		if s.To < stepsMin || s.To > stepsMax {
			return errors.New("suggestion: steps out of range")
		}
	case "tokens":
		if s.To < tokensMin || s.To > tokensMax {
			return errors.New("suggestion: tokens out of range")
		}
	case "review_prompt":
	case "remove_tool":
		has := false
		for _, t := range r.tools {
			has = has || t == s.Tool
		}
		if !has || len(r.tools) < 2 {
			return errors.New("suggestion: a tool can only be removed from a role that has it, and not its last")
		}
	default:
		return errors.New("suggestion: only steps, tokens, review_prompt and remove_tool")
	}
	return nil
}

// statsReport is `shentu dispatch stats`: the last days' numbers by role
// and the suggestions, as JSON or text.
func statsReport(cfg *Config, days int, asJSON bool, w io.Writer, now time.Time) error {
	if days < 1 || days > 30 {
		return errors.New("--days is 1 to 30")
	}
	s := newDispatchStore(cfg)
	since := now.Add(-time.Duration(days) * 24 * time.Hour)
	recs, bad, err := s.Since(since)
	if err != nil {
		return err
	}
	verdicts, fbad, err := s.Feedback(since)
	if err != nil {
		return err
	}
	stats := dispatchStats(recs, verdicts)
	sugs := suggest(stats)
	if asJSON {
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		return e.Encode(map[string]any{"days": days, "dispatches": len(recs), "unreadable_lines": bad + fbad, "roles": stats, "suggestions": sugs})
	}
	fmt.Fprintf(w, "Sub-agent dispatches, last %d days: %d (unreadable lines skipped: %d)\n", days, len(recs), bad+fbad)
	for _, st := range stats {
		reasons := make([]string, 0, len(st.Reasons))
		for k := range st.Reasons {
			reasons = append(reasons, k)
		}
		sort.Strings(reasons)
		var rs []string
		for _, k := range reasons {
			rs = append(rs, fmt.Sprintf("%s %d", k, st.Reasons[k]))
		}
		fmt.Fprintf(w, "- %s: %d runs, %d complete; incomplete: %s; %d proposals (%d refused by the gate); verdicts: %d useful, %d false positive\n",
			st.Role, st.Runs, st.Complete, cmpOr(strings.Join(rs, ", "), "none"), st.Proposals, st.Refused, st.Useful, st.FalsePos)
	}
	if len(sugs) == 0 {
		fmt.Fprintln(w, "No suggestions.")
		return nil
	}
	fmt.Fprintln(w, "Suggestions (for a person to review; Shentu changes nothing itself):")
	for _, sg := range sugs {
		switch sg.Kind {
		case "steps", "tokens":
			fmt.Fprintf(w, "- %s: %s %d -> %d (%s)\n", sg.Role, sg.Kind, sg.From, sg.To, sg.Why)
		default:
			fmt.Fprintf(w, "- %s: %s %s (%s)\n", sg.Role, sg.Kind, sg.Tool, sg.Why)
		}
	}
	return nil
}
