package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nt-neil/shentu/tools"
)

// v0.6.0 B: proposal buttons (plan c0e392, n3 B1-B8). The gate's own
// decisions are tested in tools (TestRemoteBlockCheckCodes); here, that the
// bot offers a button only for what passes it, and a press checks again.

type fakeArchive struct {
	mu   sync.Mutex
	recs map[string]dispatchRecord
}

func (f *fakeArchive) Get(id string) (dispatchRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.recs[id]
	if !ok {
		return r, errNoRecord
	}
	return r, nil
}

func (f *fakeArchive) Proposal(ref proposalRef) (dispatchRecord, proposalRecord, error) {
	r, err := f.Get(ref.Dispatch)
	if err != nil {
		return r, proposalRecord{}, err
	}
	for _, s := range r.Subs {
		for _, p := range s.Proposals {
			if p.Seq == ref.Seq {
				return r, p, nil
			}
		}
	}
	return r, proposalRecord{}, errNoProposal
}

func (f *fakeArchive) setIP(id string, seq int, ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.recs[id]
	for i := range r.Subs {
		for j := range r.Subs[i].Proposals {
			if r.Subs[i].Proposals[j].Seq == seq {
				r.Subs[i].Proposals[j].IP = ip
			}
		}
	}
}

const testDispatch = "0123456789ab"

func propRec(ps ...proposalRecord) dispatchRecord {
	for i := range ps {
		ps[i].Seq, ps[i].Action = i+1, proposeBlockIP
	}
	return dispatchRecord{V: dispatchVersion, ID: testDispatch, TS: time.Now(), Origin: originTelegram, Status: statusComplete,
		Subs: []subRecord{{Role: "incident", Status: statusComplete, Reason: reasonOK, Proposals: ps}}}
}

// gate stubs RemoteBlockCheck with a verdict per address (ok when not
// listed) and blockRun with a recorder.
type gateStub struct {
	mu    sync.Mutex
	codes map[string]tools.BlockCode
	ran   []string
}

func stubGate(t *testing.T, codes map[string]tools.BlockCode) *gateStub {
	g := &gateStub{codes: codes}
	oc, or := blockCheck, blockRun
	t.Cleanup(func() { blockCheck, blockRun = oc, or })
	blockCheck = func(_ context.Context, env *tools.Env, ip net.IP) (string, tools.BlockCode, error) {
		if !env.Remote {
			return "", tools.BlockStateError, errors.New("not checked as Telegram")
		}
		g.mu.Lock()
		defer g.mu.Unlock()
		if c, ok := g.codes[ip.String()]; ok && c != tools.BlockOK {
			return "", c, errors.New(string(c))
		}
		return "nft add element inet shentu block4 { " + ip.String() + " timeout 86400s }", tools.BlockOK, nil
	}
	blockRun = func(_ context.Context, env *tools.Env, args []byte) (any, error) {
		g.mu.Lock()
		defer g.mu.Unlock()
		if !env.Remote || strings.Contains(string(args), "override") {
			return nil, errors.New("not run as Telegram")
		}
		g.ran = append(g.ran, string(args))
		return map[string]any{}, nil
	}
	return g
}

func (g *gateStub) set(ip string, c tools.BlockCode) { g.mu.Lock(); g.codes[ip] = c; g.mu.Unlock() }
func (g *gateStub) runs() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.ran...)
}

func buttonBot(t *testing.T, rec dispatchRecord) (*bot, *fakeTelegram, *fakeArchive) {
	b, tg := testBot(t, nil, true)
	pairDirectly(t, b)
	arc := &fakeArchive{recs: map[string]dispatchRecord{rec.ID: rec}}
	b.archive = arc
	return b, tg, arc
}

func owner(b *bot) string {
	var st botState
	withBotState(b.cfg.StateDir, func(s *botState) error { st = *s; return nil })
	return pairKey(st)
}

// buttons is the proposal message's text and callback data, "" and nil when none was sent.
func buttons(tg *fakeTelegram) (string, []string) {
	for _, s := range tg.sent() {
		text, _ := s["text"].(string)
		if !strings.Contains(text, testDispatch) {
			continue
		}
		var data []string
		if rm, ok := s["reply_markup"].(map[string]any); ok {
			for _, row := range rm["inline_keyboard"].([]any) {
				for _, k := range row.([]any) {
					data = append(data, k.(map[string]any)["callback_data"].(string))
				}
			}
		}
		return text, data
	}
	return "", nil
}

func press(user int64, data string) tgUpdate {
	var u tgUpdate
	u.Callback = &struct {
		ID      string     `json:"id"`
		From    tgUser     `json:"from"`
		Data    string     `json:"data"`
		Message *tgMessage `json:"message"`
	}{ID: "q", From: tgUser{ID: user}, Data: data, Message: msg(user, pairedChat, "private", "").Message}
	return u
}

// confirmPress waits for the button confirmation and presses ✅ or ❌; it
// fails when none comes.
func confirmPress(t *testing.T, b *bot, tg *fakeTelegram, yes bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		for _, s := range tg.sent() {
			text, _ := s["text"].(string)
			rm, ok := s["reply_markup"].(map[string]any)
			if !ok || !strings.Contains(text, "nft add element") {
				continue
			}
			data := rm["inline_keyboard"].([]any)[0].([]any)[0].(map[string]any)["callback_data"].(string)
			nonce, _, _ := strings.Cut(data, ":")
			a := "n"
			if yes {
				a = "y"
			}
			b.handle(context.Background(), press(pairedUser, nonce+":"+a))
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no button confirmation was asked for")
}

func buttonEntries(t *testing.T, b *bot) []logEntry {
	var out []logEntry
	for _, e := range auditLines(t, b.cfg.StateDir) {
		if e.Origin == "dispatch_button" {
			out = append(out, e)
		}
	}
	return out
}

// B1-B4, B8: a button only for an address that passes the check now, never
// for one written another way, at most five; the callback data never holds
// the address.
func TestDispatchButtonOffer(t *testing.T) {
	rec := propRec(
		proposalRecord{IP: "203.0.113.1"},
		proposalRecord{IP: "203.0.113.2"},              // B1 unverified
		proposalRecord{IP: "203.0.113.3"},              // B2 overflow
		proposalRecord{IP: "10.0.0.1"},                 // B3 internal
		proposalRecord{IP: "203.0.113.5", Loose: true}, // B4 "::ffff:203.0.113.5" as written
		proposalRecord{IP: "::ffff:203.0.113.6"},       // B4 not canonical, Loose lost
		proposalRecord{IP: "203.0.113.7"},
		proposalRecord{IP: "203.0.113.8"},
		proposalRecord{IP: "203.0.113.9"},
		proposalRecord{IP: "2001:db8::10"},
		proposalRecord{IP: "203.0.113.11"}, // B8: the sixth that passes
	)
	g := stubGate(t, map[string]tools.BlockCode{"203.0.113.2": tools.BlockUnverified, "203.0.113.3": tools.BlockOverflow, "10.0.0.1": tools.BlockInternal})
	b, tg, _ := buttonBot(t, rec)
	b.offerProposals(context.Background(), pairedChat, testDispatch, owner(b))
	text, data := buttons(tg)
	if len(data) != maxProposalButtons {
		t.Fatalf("%d buttons, want %d: %v\n%s", len(data), maxProposalButtons, data, text)
	}
	for _, d := range data {
		if len(d) > 64 || strings.Contains(d, "203.0.113") || strings.Contains(d, "2001:db8") {
			t.Errorf("callback data %q holds the address or is too long", d)
		}
		ref, err := parseProposalRef(d)
		if err != nil || ref.Dispatch != testDispatch {
			t.Errorf("callback data %q: %v", d, err)
		}
		if ref.Seq == 2 || ref.Seq == 3 || ref.Seq == 4 || ref.Seq == 5 || ref.Seq == 6 || ref.Seq == 11 {
			t.Errorf("a button for proposal %d", ref.Seq)
		}
	}
	for _, w := range []string{"unverified", "overflow", "internal", "not_canonical"} {
		if !strings.Contains(text, w) {
			t.Errorf("the reason %q is not said:\n%s", w, text)
		}
	}
	if len(g.runs()) != 0 {
		t.Error("offering buttons blocked something")
	}
}

// No button without control (interaction < 3 or no CAP_NET_ADMIN), for a
// dispatch that is not Telegram's, or one past buttonTTL.
func TestDispatchButtonNotOffered(t *testing.T) {
	stubGate(t, map[string]tools.BlockCode{})
	for _, c := range []struct {
		name string
		edit func(*bot, *dispatchRecord)
	}{
		{"no control", func(b *bot, _ *dispatchRecord) { b.canAct = false }},
		{"from shentu chat", func(_ *bot, r *dispatchRecord) { r.Origin = originChat }},
		{"automatic", func(_ *bot, r *dispatchRecord) { r.Origin = originAuto }},
		{"expired", func(_ *bot, r *dispatchRecord) { r.TS = time.Now().Add(-buttonTTL - time.Minute) }},
	} {
		rec := propRec(proposalRecord{IP: "203.0.113.1"})
		b, tg, arc := buttonBot(t, rec)
		c.edit(b, &rec)
		arc.recs[rec.ID] = rec
		b.offerProposals(context.Background(), pairedChat, testDispatch, owner(b))
		if _, data := buttons(tg); len(data) != 0 {
			t.Errorf("%s: buttons %v", c.name, data)
		}
	}
}

func offerOne(t *testing.T, rec dispatchRecord) (*bot, *fakeTelegram, *fakeArchive, *gateStub, []string) {
	g := stubGate(t, map[string]tools.BlockCode{})
	b, tg, arc := buttonBot(t, rec)
	b.offerProposals(context.Background(), pairedChat, testDispatch, owner(b))
	_, data := buttons(tg)
	if len(data) == 0 {
		t.Fatal("no button was offered")
	}
	return b, tg, arc, g, data
}

// B5: the group goes away after the button was offered: the press checks
// again and refuses, before any confirmation.
func TestDispatchButtonPressChecksAgain(t *testing.T) {
	b, tg, _, g, data := offerOne(t, propRec(proposalRecord{IP: "203.0.113.1"}))
	g.set("203.0.113.1", tools.BlockWeak)
	b.handle(context.Background(), press(pairedUser, data[0]))
	answered(t, b)
	if r := g.runs(); len(r) != 0 {
		t.Fatalf("blocked after its group was downgraded: %v", r)
	}
	for _, s := range tg.sent() {
		if strings.Contains(s["text"].(string), "nft add element") {
			t.Error("a confirmation was asked for an address the check refuses")
		}
	}
	es := buttonEntries(t, b)
	if len(es) != 1 || !strings.Contains(es[0].Error, "weak") || es[0].Dispatch != testDispatch {
		t.Errorf("audit: %+v", es)
	}
}

// The whole press: checked, confirmed, blocked as Telegram, logged.
func TestDispatchButtonPressBlocks(t *testing.T) {
	b, tg, _, g, data := offerOne(t, propRec(proposalRecord{IP: "203.0.113.1"}))
	b.handle(context.Background(), press(pairedUser, data[0]))
	confirmPress(t, b, tg, true)
	answered(t, b)
	r := g.runs()
	if len(r) != 1 || !strings.Contains(r[0], `"ip":"203.0.113.1"`) {
		t.Fatalf("runs: %v", r)
	}
	es := buttonEntries(t, b)
	if len(es) != 1 || !es[0].OK || !es[0].Confirmed {
		t.Errorf("audit: %+v", es)
	}
}

// B6: forged and replayed presses, a press from another pairing, and an
// archive whose address changed are refused.
func TestDispatchButtonForged(t *testing.T) {
	ctx := context.Background()
	t.Run("forged", func(t *testing.T) {
		b, _, _, g, data := offerOne(t, propRec(proposalRecord{IP: "203.0.113.1"}, proposalRecord{IP: "203.0.113.2"}))
		for _, d := range []string{
			proposalRef{Dispatch: "ba9876543210", Seq: 1}.String(), // another dispatch id
			proposalRef{Dispatch: testDispatch, Seq: 7}.String(),   // a seq never offered
		} {
			b.handle(ctx, press(pairedUser, d))
			answered(t, b)
		}
		b.handle(ctx, press(2002, data[0])) // a stranger
		answered(t, b)
		if r := g.runs(); len(r) != 0 {
			t.Errorf("runs: %v", r)
		}
	})
	t.Run("replayed", func(t *testing.T) {
		b, tg, _, g, data := offerOne(t, propRec(proposalRecord{IP: "203.0.113.1"}))
		b.handle(ctx, press(pairedUser, data[0]))
		confirmPress(t, b, tg, false) // declined
		answered(t, b)
		n := len(tg.sent())
		b.handle(ctx, press(pairedUser, data[0])) // pressed again
		answered(t, b)
		for _, s := range tg.sent()[n:] {
			if strings.Contains(s["text"].(string), "nft add element") {
				t.Error("a used button asked for confirmation again")
			}
		}
		if r := g.runs(); len(r) != 0 {
			t.Errorf("runs: %v", r)
		}
	})
	t.Run("another pairing", func(t *testing.T) {
		b, _, _, g, data := offerOne(t, propRec(proposalRecord{IP: "203.0.113.1"}))
		withBotState(b.cfg.StateDir, func(s *botState) error { s.PairedAt = time.Now(); return nil }) // paired again
		b.handle(ctx, press(pairedUser, data[0]))
		answered(t, b)
		if r := g.runs(); len(r) != 0 {
			t.Errorf("runs: %v", r)
		}
	})
	t.Run("archive changed", func(t *testing.T) {
		b, _, arc, g, data := offerOne(t, propRec(proposalRecord{IP: "203.0.113.1"}))
		arc.setIP(testDispatch, 1, "203.0.113.99") // passes the check, not what was offered
		b.handle(ctx, press(pairedUser, data[0]))
		answered(t, b)
		if r := g.runs(); len(r) != 0 {
			t.Errorf("runs: %v", r)
		}
	})
	t.Run("expired", func(t *testing.T) {
		b, _, _, g, data := offerOne(t, propRec(proposalRecord{IP: "203.0.113.1"}))
		withBotState(b.cfg.StateDir, func(s *botState) error {
			s.Buttons[testDispatch].At = time.Now().Add(-buttonTTL - time.Minute)
			return nil
		})
		b.handle(ctx, press(pairedUser, data[0]))
		answered(t, b)
		if r := g.runs(); len(r) != 0 {
			t.Errorf("runs: %v", r)
		}
	})
}

// B7: [bot] confirm = 4 (no confirmation) still asks for the press.
func TestDispatchButtonConfirmFour(t *testing.T) {
	g := stubGate(t, map[string]tools.BlockCode{})
	b, tg, _ := buttonBot(t, propRec(proposalRecord{IP: "203.0.113.1"}))
	b.cfg.Bot.Confirm = 4
	b.offerProposals(context.Background(), pairedChat, testDispatch, owner(b))
	_, data := buttons(tg)
	if len(data) != 1 {
		t.Fatalf("buttons: %v", data)
	}
	b.handle(context.Background(), press(pairedUser, data[0]))
	time.Sleep(100 * time.Millisecond)
	if r := g.runs(); len(r) != 0 {
		t.Fatalf("blocked without the confirmation press: %v", r)
	}
	confirmPress(t, b, tg, true)
	answered(t, b)
	if r := g.runs(); len(r) != 1 {
		t.Errorf("runs: %v", r)
	}
}

// The buttons use the real check unless a test replaces it.
func TestDispatchButtonUsesRemoteBlockCheck(t *testing.T) {
	if blockCheck == nil || (&bot{}).blockWord(tools.BlockOK) == "" {
		t.Fatal("no check")
	}
	_, code, _ := blockCheck(context.Background(), &tools.Env{}, net.ParseIP("127.0.0.1"))
	if code == tools.BlockOK {
		t.Error("the default check lets loopback through")
	}
}
