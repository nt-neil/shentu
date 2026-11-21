package main

import (
	"context"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nt-neil/shentu/detect"
	"github.com/nt-neil/shentu/tools"
)

// The v0.5.3 real-bot acceptance (the press got no answer at all): an automatic incident dispatch's
// proposal button, pressed, with the real RemoteBlockCheck and a verified
// L3 group listing the address, asks for ✅ and blocks once pressed.
func TestAutoProposalPressRealGateFlow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("block_ip is not offered on Windows")
	}
	ctx := context.Background()
	b, tg := testBot(t, nil, true)
	pairDirectly(t, b)
	b.canAct = true
	now := time.Now()
	a := &detect.Attacks{Version: 1, Groups: map[string]*detect.Group{}, Overflow: map[string]*detect.Group{}}
	key := "203.0.113.0/24|code@/srv/accapp/app.py:14|L3|v"
	a.Groups[key] = &detect.Group{Key: key, Prefix: "203.0.113.0/24", Entry: "code@/srv/accapp/app.py:14", Level: detect.LevelSuccess,
		IPs: []string{"203.0.113.40"}, Reasons: []string{"marker"}, First: now.Add(-time.Minute), Last: now, Count: 3}
	if err := a.Save(b.cfg.StateDir, now); err != nil {
		t.Fatal(err)
	}
	tools.SetStateDir(b.cfg.StateDir)
	t.Cleanup(func() { tools.SetStateDir("") })
	if _, code, err := tools.RemoteBlockCheck(ctx, &tools.Env{Remote: true}, []byte{203, 0, 113, 40}); code != tools.BlockOK {
		t.Fatalf("the gate itself: %s %v", code, err)
	}
	rec := propRec(proposalRecord{IP: "203.0.113.40"})
	rec.Origin = originAuto
	b.archive = &fakeArchive{recs: map[string]dispatchRecord{rec.ID: rec}}
	var mu sync.Mutex
	var ran []string
	old := blockRun
	blockRun = func(_ context.Context, env *tools.Env, args []byte) (any, error) {
		mu.Lock()
		defer mu.Unlock()
		ran = append(ran, string(args))
		return map[string]any{}, nil
	}
	t.Cleanup(func() { blockRun = old })
	b.offerProposals(ctx, pairedChat, testDispatch, owner(b), originAuto)
	_, data := buttons(tg)
	if len(data) != 1 {
		t.Fatalf("buttons: %v", data)
	}
	n := len(tg.sent())
	b.handle(ctx, press(pairedUser, data[0]))
	confirmPress(t, b, tg, true)
	answered(t, b)
	mu.Lock()
	defer mu.Unlock()
	if len(ran) != 1 {
		var texts []string
		for _, s := range tg.sent()[n:] {
			texts = append(texts, s["text"].(string))
		}
		t.Errorf("blocks run: %v; sent after the press: %q", ran, texts)
	}
}

// pressTexts are the texts sent after the first n messages.
func pressTexts(tg *fakeTelegram, n int) []string {
	var out []string
	for _, s := range tg.sent()[n:] {
		out = append(out, s["text"].(string))
	}
	return out
}

// A press whose checks hang is answered at once, then refused when they
// run out of time; it is never left without an answer.
func TestProposalPressCheckHangs(t *testing.T) {
	b, tg, _, _, data := offerOne(t, propRec(proposalRecord{IP: "203.0.113.1"}))
	old, oldT := blockCheck, pressCheckTimeout
	blockCheck = func(ctx context.Context, _ *tools.Env, _ net.IP) (string, tools.BlockCode, error) {
		<-ctx.Done() // a check that would not end on its own
		return "", tools.BlockOK, nil
	}
	pressCheckTimeout = 200 * time.Millisecond
	t.Cleanup(func() { blockCheck, pressCheckTimeout = old, oldT })
	n := len(tg.sent())
	b.handle(context.Background(), press(pairedUser, data[0]))
	waitFor(t, "the first answer", func() bool { return len(tg.sent()) > n })
	if got := pressTexts(tg, n); !strings.Contains(got[0], "203.0.113.1") || !strings.Contains(got[0], "…") {
		t.Errorf("first answer: %q", got)
	}
	answered(t, b)
	got := pressTexts(tg, n)
	if len(got) < 2 || !strings.Contains(got[len(got)-1], b.blockWord(tools.BlockStateError)) {
		t.Errorf("after the checks ran out of time: %q", got)
	}
	var press, refused bool
	for _, e := range auditLines(t, b.cfg.StateDir) {
		press = press || e.Tool == "proposal_press"
		refused = refused || e.Tool == "block_ip" && strings.Contains(e.Error, "state_error")
	}
	if !press || !refused {
		t.Errorf("log: press %v, refused %v", press, refused)
	}
}

// A press whose checks panic is answered and logged; the bot goes on.
func TestProposalPressPanics(t *testing.T) {
	b, tg, _, _, data := offerOne(t, propRec(proposalRecord{IP: "203.0.113.1"}))
	old := blockCheck
	blockCheck = func(context.Context, *tools.Env, net.IP) (string, tools.BlockCode, error) { panic("marker") }
	t.Cleanup(func() { blockCheck = old })
	n := len(tg.sent())
	b.handle(context.Background(), press(pairedUser, data[0]))
	answered(t, b)
	if got := pressTexts(tg, n); len(got) < 2 || got[len(got)-1] != b.t("prop_failed") {
		t.Errorf("answers: %q", got)
	}
}
