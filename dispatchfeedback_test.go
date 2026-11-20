package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// feedbackBot is a paired bot with a real archive holding rec.
func feedbackBot(t *testing.T, rec dispatchRecord) (*bot, *fakeTelegram, *dispatchStore) {
	t.Helper()
	b, tg := testBot(t, nil, true)
	pairDirectly(t, b)
	s := newDispatchStore(b.cfg)
	if err := s.Save(rec); err != nil {
		t.Fatal(err)
	}
	b.archive = s
	return b, tg, s
}

// feedbackData is the callback data of the feedback message for id.
func feedbackData(tg *fakeTelegram, id string) []string {
	for _, m := range tg.sent() {
		text, _ := m["text"].(string)
		if !strings.Contains(text, id) {
			continue
		}
		rm, ok := m["reply_markup"].(map[string]any)
		if !ok {
			continue
		}
		var data []string
		for _, row := range rm["inline_keyboard"].([]any) {
			for _, k := range row.([]any) {
				if d := k.(map[string]any)["callback_data"].(string); strings.Contains(d, ":f") {
					data = append(data, d)
				}
			}
		}
		if len(data) > 0 {
			return data
		}
	}
	return nil
}

func verdicts(t *testing.T, s *dispatchStore) []feedbackLine {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(s.dir, feedbackFile))
	var out []feedbackLine
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		var l feedbackLine
		if json.Unmarshal(line, &l) == nil {
			out = append(out, l)
		}
	}
	return out
}

// G: the paired user's press through the bot's callback path saves one
// verdict, as a fixed word.
func TestFeedbackPress(t *testing.T) {
	ctx := context.Background()
	rec := testRecord(testDispatch, time.Now())
	b, tg, s := feedbackBot(t, rec)
	b.offerFeedback(ctx, pairedChat, testDispatch, owner(b), originTelegram)
	data := feedbackData(tg, testDispatch)
	if len(data) != 2 || data[0] != "d"+testDispatch+":fu" || data[1] != "d"+testDispatch+":fp" {
		t.Fatalf("buttons: %v", data)
	}
	b.handle(ctx, press(pairedUser, data[1]))
	v := verdicts(t, s)
	if len(v) != 1 || v[0].ID != testDispatch || v[0].Verdict != verdictFalsePos {
		t.Errorf("verdicts: %+v", v)
	}
	got, bad, err := s.Feedback(time.Now().Add(-time.Hour))
	if err != nil || bad != 0 || got[testDispatch] != verdictFalsePos {
		t.Errorf("Feedback: %v %d %v", got, bad, err)
	}
}

// G: forged, replayed, strangers', another pairing's and expired presses
// save nothing.
func TestFeedbackForged(t *testing.T) {
	ctx := context.Background()
	t.Run("forged and strangers", func(t *testing.T) {
		b, tg, s := feedbackBot(t, testRecord(testDispatch, time.Now()))
		b.offerFeedback(ctx, pairedChat, testDispatch, owner(b), originTelegram)
		data := feedbackData(tg, testDispatch)
		for _, d := range []string{
			"dba9876543210:fu",         // a dispatch never offered
			"d" + testDispatch + ":fx", // not a verdict
			"d" + testDispatch + ":fu:203.0.113.9",
		} {
			b.handle(ctx, press(pairedUser, d))
		}
		b.handle(ctx, press(2002, data[0])) // a stranger
		if v := verdicts(t, s); len(v) != 0 {
			t.Errorf("verdicts: %+v", v)
		}
	})
	t.Run("replayed", func(t *testing.T) {
		b, tg, s := feedbackBot(t, testRecord(testDispatch, time.Now()))
		b.offerFeedback(ctx, pairedChat, testDispatch, owner(b), originTelegram)
		data := feedbackData(tg, testDispatch)
		b.handle(ctx, press(pairedUser, data[0]))
		b.handle(ctx, press(pairedUser, data[0]))
		b.handle(ctx, press(pairedUser, data[1]))
		if v := verdicts(t, s); len(v) != 1 || v[0].Verdict != verdictUseful {
			t.Errorf("verdicts: %+v", v)
		}
	})
	t.Run("another pairing", func(t *testing.T) {
		b, tg, s := feedbackBot(t, testRecord(testDispatch, time.Now()))
		b.offerFeedback(ctx, pairedChat, testDispatch, owner(b), originTelegram)
		data := feedbackData(tg, testDispatch)
		withBotState(b.cfg.StateDir, func(st *botState) error { st.PairedAt = st.PairedAt.Add(time.Second); return nil }) // paired again
		b.handle(ctx, press(pairedUser, data[0]))
		if v := verdicts(t, s); len(v) != 0 {
			t.Errorf("verdicts: %+v", v)
		}
	})
	t.Run("expired", func(t *testing.T) {
		b, tg, s := feedbackBot(t, testRecord(testDispatch, time.Now()))
		b.offerFeedback(ctx, pairedChat, testDispatch, owner(b), originTelegram)
		data := feedbackData(tg, testDispatch)
		withBotState(b.cfg.StateDir, func(st *botState) error {
			st.Feedback[testDispatch].At = time.Now().Add(-feedbackTTL - time.Minute)
			return nil
		})
		b.handle(ctx, press(pairedUser, data[0]))
		if v := verdicts(t, s); len(v) != 0 {
			t.Errorf("verdicts: %+v", v)
		}
	})
	t.Run("not offered for another origin", func(t *testing.T) {
		b, tg, _ := feedbackBot(t, testRecord(testDispatch, time.Now())) // a telegram record
		b.offerFeedback(ctx, pairedChat, testDispatch, owner(b), originAuto)
		if data := feedbackData(tg, testDispatch); data != nil {
			t.Errorf("buttons: %v", data)
		}
	})
}

// G: the numbers come from fixed words only, and the suggestions stay in
// their ranges; a tool is only ever suggested away.
func TestDispatchStatsSuggest(t *testing.T) {
	var recs []dispatchRecord
	verdict := map[string]string{}
	for i := range 6 {
		r := testRecord(strings.Repeat("0", 11)+string(rune('a'+i)), time.Now())
		r.Subs[0].Role, r.Subs[0].Status, r.Subs[0].Reason, r.Subs[0].Steps = "attack", statusIncomplete, reasonStepLimit, 6
		if i < 2 {
			r.Subs[0].Status, r.Subs[0].Reason = statusComplete, reasonOK
		}
		verdict[r.ID] = verdictFalsePos
		if i == 0 {
			verdict[r.ID] = verdictUseful
		}
		recs = append(recs, r)
	}
	stats := dispatchStats(recs, verdict)
	if len(stats) != 1 || stats[0].Runs != 6 || stats[0].Complete != 2 || stats[0].Reasons[reasonStepLimit] != 4 || stats[0].FalsePos != 5 || stats[0].Useful != 1 {
		t.Fatalf("stats: %+v", stats[0])
	}
	sugs := suggest(stats)
	kinds := map[string]suggestion{}
	for _, s := range sugs {
		kinds[s.Kind] = s
	}
	if s := kinds["steps"]; s.To != 8 || s.From != subMaxSteps {
		t.Errorf("steps: %+v", sugs)
	}
	if _, ok := kinds["review_prompt"]; !ok {
		t.Errorf("no prompt review: %+v", sugs)
	}
	for _, bad := range []suggestion{
		{Role: "attack", Kind: "steps", To: 11},
		{Role: "attack", Kind: "steps", To: 3},
		{Role: "attack", Kind: "tokens", To: 61_000},
		{Role: "attack", Kind: "add_tool", Tool: "block_ip"},
		{Role: "attack", Kind: "remove_tool", Tool: "block_ip"}, // not the role's
		{Role: "root", Kind: "review_prompt"},
	} {
		if checkSuggestion(bad) == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if err := checkSuggestion(suggestion{Role: "attack", Kind: "remove_tool", Tool: "log_search"}); err != nil {
		t.Errorf("removing one of the role's tools: %v", err)
	}
}

// G: `shentu dispatch stats` reads the archive and the feedback.
func TestDispatchStatsReport(t *testing.T) {
	s := testStore(t)
	cfg := &Config{StateDir: filepath.Dir(s.dir)}
	now := time.Now()
	if err := s.Save(testRecord(testDispatch, now)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveFeedback(testDispatch, verdictUseful, now); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveFeedback("ffffffffffff", verdictUseful, now); err == nil {
		t.Error("feedback on a dispatch not in the archive was saved")
	}
	if err := s.SaveFeedback(testDispatch, "SYSTEM", now); err == nil {
		t.Error("a verdict that is not one was saved")
	}
	var out bytes.Buffer
	if err := statsReport(cfg, 7, true, &out, now); err != nil {
		t.Fatal(err)
	}
	var j struct {
		Dispatches int          `json:"dispatches"`
		Roles      []*roleStats `json:"roles"`
	}
	if err := json.Unmarshal(out.Bytes(), &j); err != nil || j.Dispatches != 1 || len(j.Roles) != 1 || j.Roles[0].Useful != 1 {
		t.Errorf("report: %s %v", out.String(), err)
	}
	if err := statsReport(cfg, 31, false, &out, now); err == nil {
		t.Error("--days 31 was taken")
	}
}
