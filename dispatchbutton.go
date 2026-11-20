package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/nt-neil/shentu/detect"
	"github.com/nt-neil/shentu/hostenv"
	"github.com/nt-neil/shentu/tools"
)

// Proposal buttons (phase 2, B). After a Telegram answer that dispatched
// sub-agents, each address they proposed to block is checked as block_ip
// from Telegram would check it (tools.RemoteBlockCheck); one that passes
// gets a button, any other is listed with the check's fixed word only. A
// button carries the dispatch id and the proposal's seq, never the address.
// Pressing it reads the proposal back from the archive and runs every check
// again, then the button confirmation (never skipped, [bot] confirm = 4
// included), then block_ip, whose Run checks once more. A button works once,
// for its pairing only, within buttonTTL of its dispatch.

const maxProposalButtons = 5

// proposalArchive is what the buttons read of the dispatch archive
// (dispatchStore).
type proposalArchive interface {
	Get(id string) (dispatchRecord, error)
	Proposal(ref proposalRef) (dispatchRecord, proposalRecord, error)
}

// buttonSet is the buttons offered under one dispatch, kept in bot.json so a
// press is checked against what was offered, after a restart too.
type buttonSet struct {
	Pair string         `json:"pair"` // the pairing they were offered to (user id @ paired time)
	At   time.Time      `json:"at"`   // the dispatch's time: they expire buttonTTL after it
	IPs  map[int]string `json:"ips"`  // seq -> the canonical address offered
	Used map[int]bool   `json:"used,omitempty"`
}

// The checks and the block itself; tests replace them.
var (
	blockCheck = tools.RemoteBlockCheck
	blockRun   = func(ctx context.Context, env *tools.Env, args []byte) (any, error) {
		t, _ := tools.Find("block_ip")
		return t.Run(ctx, env, args)
	}
)

func pairKey(st botState) string { return fmt.Sprintf("%d@%d", st.UserID, st.PairedAt.UnixNano()) }

// proposalCode is the fixed word for one proposal now: not_canonical for an
// address the sub-agent wrote another way, else RemoteBlockCheck's.
func (b *bot) proposalCode(ctx context.Context, p proposalRecord) (preview string, ip net.IP, code tools.BlockCode) {
	ip = net.ParseIP(p.IP)
	if p.Loose || ip == nil || hostenv.CanonicalIP(p.IP) != p.IP || p.Action != proposeBlockIP {
		return "", nil, tools.BlockNotCanonical
	}
	env := *b.env
	env.Remote = true
	preview, code, _ = blockCheck(ctx, &env, ip)
	return preview, ip, code
}

// offerProposals sends the proposals of dispatch id with a button for each
// that passes the checks now (at most maxProposalButtons). owner is the
// pairing the answer belonged to; origin is the dispatch's that may be
// offered (originTelegram for the bot's own answer, originAuto for C).
func (b *bot) offerProposals(ctx context.Context, chat int64, id, owner, origin string) {
	if !b.canAct || b.archive == nil || id == "" {
		return
	}
	rec, err := b.archive.Get(id)
	if err != nil || rec.Origin != origin || time.Since(rec.TS) > buttonTTL {
		return
	}
	var lines, unsaved []string // unsaved: the lines if the buttons cannot be kept
	var rows [][]map[string]string
	set := &buttonSet{Pair: owner, At: rec.TS, IPs: map[int]string{}}
	for _, s := range rec.Subs {
		for _, p := range s.Proposals {
			_, ip, code := b.proposalCode(ctx, p)
			addr := detect.Printable(p.IP)
			switch {
			case code != tools.BlockOK:
				lines = append(lines, fmt.Sprintf("%d. %s — "+b.t("prop_nobutton"), p.Seq, addr, b.blockWord(code)))
			case len(rows) == maxProposalButtons:
				lines = append(lines, fmt.Sprintf("%d. %s — %s", p.Seq, addr, b.t("prop_more")))
			default:
				lines = append(lines, fmt.Sprintf("%d. %s — %s", p.Seq, addr, b.t("prop_button")))
				unsaved = append(unsaved, fmt.Sprintf("%d. %s — "+b.t("prop_nobutton"), p.Seq, addr, b.blockWord(tools.BlockStateError)))
				ref := proposalRef{Dispatch: id, Seq: p.Seq}
				rows = append(rows, []map[string]string{{"text": fmt.Sprintf(b.t("prop_block"), ip), "callback_data": ref.String()}})
				set.IPs[p.Seq] = ip.String()
			}
		}
	}
	if len(lines) == 0 {
		return
	}
	var kb any
	if len(rows) > 0 {
		ok := true
		err := withBotState(b.cfg.StateDir, func(s *botState) error {
			if pairKey(*s) != owner || s.Paused != "" { // the pairing changed meanwhile, or the bot stopped
				ok = false
				return nil
			}
			for k, v := range s.Buttons {
				if time.Since(v.At) > buttonTTL {
					delete(s.Buttons, k)
				}
			}
			if s.Buttons == nil {
				s.Buttons = map[string]*buttonSet{}
			}
			s.Buttons[id] = set
			return nil
		})
		switch {
		case !ok:
			return
		case err != nil:
			// A button bot.json does not hold could not be checked when
			// pressed: the reasons only.
			n := 0
			for i, l := range lines {
				if strings.HasSuffix(l, b.t("prop_button")) {
					lines[i], n = unsaved[n], n+1
				}
			}
		default:
			kb = map[string]any{"inline_keyboard": rows}
		}
	}
	title := "prop_title"
	if origin == originAuto {
		title = "prop_title_auto"
	}
	b.send(ctx, chat, fmt.Sprintf(b.t(title), id)+"\n"+strings.Join(lines, "\n"), kb)
}

// offerAutoButtons is how an automatic incident dispatch (C) offers its
// proposals: from the patrol, to the paired chat, as the bot's answers do,
// once the record is in the archive. Nothing is sent without a paired,
// running bot that may act ([bot] interaction >= 3); the press is the bot
// service's, with every check there (CAP_NET_ADMIN included).
func offerAutoButtons(ctx context.Context, cfg *Config, env *tools.Env, id string) error {
	token := botToken(cfg)
	if token == "" || cfg.Bot.Interaction < 3 {
		return nil
	}
	var st botState
	if err := withBotState(cfg.StateDir, func(s *botState) error { st = *s; return nil }); err != nil {
		return err
	}
	if st.UserID == 0 || st.ChatID == 0 || st.Paused != "" {
		return nil
	}
	b := &bot{cfg: cfg, env: env, token: token, api: telegramBotAPI, hc: &http.Client{Timeout: 30 * time.Second},
		archive: newDispatchStore(cfg), canAct: true}
	b.offerProposals(ctx, st.ChatID, id, pairKey(st), originAuto)
	return nil
}

// pressProposal handles a press of a proposal button by the paired user.
func (b *bot) pressProposal(ctx context.Context, st botState, ref proposalRef) {
	chat := st.ChatID
	entry := logEntry{Actor: "bot", Tool: "block_ip", Dispatch: ref.Dispatch, Origin: "dispatch_button", Args: ref.String()}
	refuse := func(why string, text string) {
		entry.Error = why
		b.log.write(entry)
		b.send(ctx, chat, text, nil)
	}
	if !b.canAct || b.archive == nil {
		refuse("proposal buttons are off (interaction < 3 or no CAP_NET_ADMIN)", b.t("prop_gone"))
		return
	}
	if !openNow(b.cfg.Bot.Protection, time.Now()) {
		b.send(ctx, chat, b.t("closed"), nil)
		return
	}
	b.mu.Lock()
	if b.busy {
		b.mu.Unlock()
		b.send(ctx, chat, b.t("busy"), nil) // the button stays: nothing was decided
		return
	}
	b.busy = true
	b.mu.Unlock()
	// Taken before anything else: a second press of the same button, now or
	// after a restart, finds it used.
	offered, why := "", "no such button"
	err := withBotState(b.cfg.StateDir, func(s *botState) error {
		set := s.Buttons[ref.Dispatch]
		switch {
		case set == nil:
		case set.Pair != pairKey(st) || pairKey(*s) != pairKey(st):
			why = "the button was offered to another pairing"
		case time.Since(set.At) > buttonTTL:
			why = "the button expired"
		case set.IPs[ref.Seq] == "":
			why = "no such button"
		case set.Used[ref.Seq]:
			why = "the button was already pressed"
		default:
			if set.Used == nil {
				set.Used = map[int]bool{}
			}
			set.Used[ref.Seq] = true
			offered, why = set.IPs[ref.Seq], ""
		}
		return nil
	})
	go func() {
		defer func() { b.mu.Lock(); b.busy = false; b.mu.Unlock() }()
		if err != nil {
			// Used is not on disk: the button could be pressed again.
			refuse("the button's use could not be saved: "+mask(err.Error()), b.t("prop_unsaved"))
			return
		}
		if why != "" {
			refuse(why, b.t("prop_gone"))
			return
		}
		rec, p, err := b.archive.Proposal(ref)
		switch {
		case err != nil:
			refuse("the proposal could not be read back: "+mask(err.Error()), b.t("prop_gone"))
			return
		case rec.Origin != originTelegram && rec.Origin != originAuto || time.Since(rec.TS) > buttonTTL:
			refuse("the dispatch is not a Telegram or automatic one within the button's time", b.t("prop_gone"))
			return
		case p.IP != offered:
			refuse("the archive's address differs from the one the button was offered for", b.t("prop_gone"))
			return
		}
		// From the start: RemoteRefused, Preview, blockGate (remoteGate).
		preview, ip, code := b.proposalCode(ctx, p)
		if code != tools.BlockOK {
			refuse("refused at press: "+string(code), fmt.Sprintf(b.t("prop_refused"), detect.Printable(p.IP), b.blockWord(code)))
			return
		}
		entry.Preview = mask(preview)
		if !b.confirm(ctx, chat, "block_ip", preview, true) {
			entry.Error = "declined by operator"
			b.log.write(entry)
			return
		}
		entry.Confirmed = true
		env := *b.env
		env.Remote = true
		tctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		if _, err := blockRun(tctx, &env, tools.ProposalBlockArgs(ip)); err != nil {
			// The message is for the log: a refusal quotes what attackers
			// logged. The chat gets its fixed word, or that it failed.
			entry.Error = mask(err.Error())
			b.log.write(entry)
			if code, ok := tools.RefusalCode(err); ok {
				b.send(ctx, chat, fmt.Sprintf(b.t("prop_refused"), detect.Printable(p.IP), b.blockWord(code)), nil)
			} else {
				b.send(ctx, chat, b.t("prop_failed"), nil)
			}
			return
		}
		entry.OK = true
		b.log.write(entry)
		b.send(ctx, chat, fmt.Sprintf(b.t("prop_blocked"), ip), nil)
	}()
}

// blockWord is a BlockCode as the operator reads it.
func (b *bot) blockWord(code tools.BlockCode) string {
	if w, ok := blockWords[code]; ok {
		if b.zh() {
			return w[1]
		}
		return w[0]
	}
	return string(code)
}

var blockWords = map[tools.BlockCode][2]string{
	tools.BlockUnverified:   {"its records cannot be believed (unverified)", "紀錄來源不可信（unverified）"},
	tools.BlockOverflow:     {"only in an overflow summary (overflow)", "只出現在溢出彙總（overflow）"},
	tools.BlockWeak:         {"attempts not strong enough (weak)", "攻擊跡象不足（weak）"},
	tools.BlockInternal:     {"an internal or own address (internal)", "內部或本機位址（internal）"},
	tools.BlockLockout:      {"gateway, DNS or an SSH session (lockout)", "閘道、DNS 或 SSH 連線中的位址（lockout）"},
	tools.BlockNotCanonical: {"the address was written another way (not_canonical)", "位址寫法不標準（not_canonical）"},
	tools.BlockNoEvidence:   {"no verified evidence (no_evidence)", "沒有查證過的證據（no_evidence）"},
	tools.BlockStateError:   {"the records could not be read (state_error)", "紀錄讀不到（state_error）"},
}
