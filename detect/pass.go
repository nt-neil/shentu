package detect

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nt-neil/shentu/detect/sig"
	"github.com/nt-neil/shentu/hostenv"
)

// One patrol round's detection (plan 0743f0, P5): the host's web logs and
// application units read since the last round, every request matched and
// judged against the vulnerability surface, its attempts counted in
// attacks.json, raised to L3 by this round's error logs and the routes'
// baselines. The caller notifies what is Due, says Notified for each sent,
// sends NoticeText, then Save and Close. Nothing here sends or blocks.

// Sources are where a round finds its logs (hostenv.LinuxCollector).
type Sources interface {
	WebLogs(hostenv.Source) hostenv.Obs[[]hostenv.LogSource]
	AppUnits(hostenv.Source) hostenv.Obs[[]hostenv.AppUnit]
	WebAccounts(hostenv.Source) hostenv.WebAccounts
}

// PassInput is what a round reads and judges with.
type PassInput struct {
	Src      hostenv.Source
	Sources  Sources
	StateDir string
	Surface  Surface
	Sigs     []sig.Signature
	Now      time.Time
	Budget   *Budget        // shared by every log of the round
	Loc      *time.Location // the host's zone, for error logs' times without one
	// CodeRoots: where the audited code lives (Evidence.CodeRoots).
	CodeRoots []string
}

// SourceRead is what reading one log or unit gave.
type SourceRead struct {
	Key      string     `json:"key"`  // the log's path, or journald:<unit>
	Kind     string     `json:"kind"` // access, error, php_error, journal
	Verified bool       `json:"verified"`
	Read     ReadResult `json:"read"`
	Signals  *Signals   `json:"signals,omitempty"` // an access log's
	Err      string     `json:"error,omitempty"`
}

// PassRound is a round read and judged, its state held (attacks.lock)
// until Close.
type PassRound struct {
	Round   Round        `json:"round"`
	Sources []SourceRead `json:"sources"`
	// Notices are what the round itself says, in Chinese, apart from any
	// group's alert: sources that could not be read or listed, cursors
	// read again from the start, stuck cursors, signals of tampering.
	Notices []string `json:"notices,omitempty"`

	dir       string
	now       time.Time
	in        PassInput
	attacks   *Attacks
	baselines *Baselines
	cursors   *Cursors
	dropped   map[string]string

	// mu guards the state while Run may still be going: a round given up
	// (Abandon) keeps what its finished sources gave; a read still stuck
	// changes nothing after it.
	mu        sync.Mutex
	abandoned bool
	current   string // the source being read
}

// PassTimeoutsWarn: this many rounds in a row given up is said as more
// than a slow round (a log on a stuck mount, a log too large to read).
const PassTimeoutsWarn = 3

// Signals worth a notice: an attacker making lines unparseable, splitting
// them two ways, or padding them past the cut.
const (
	NoticeUnparsedMin   = 20 // lines unparsed in one log's round, and
	NoticeUnparsedShare = 10 // at least this share of its lines (percent)
)

// knownFormats are the formats whose client field is the connection's
// address as the server wrote it.
var knownFormats = map[string]bool{"combined": true, "common": true, "main": true, "vhost_combined": true, "combinedio": true}

// RunPass reads and judges one round (NewPass, then Run).
func RunPass(ctx context.Context, in PassInput) (*PassRound, error) {
	p, err := NewPass(in)
	if err != nil {
		return nil, err
	}
	p.Run(ctx)
	return p, nil
}

// NewPass loads a round's state. It takes attacks.lock (held until Close:
// another round waits); a state file that cannot be read starts again,
// said in the notices, never as "nothing seen".
func NewPass(in PassInput) (*PassRound, error) {
	a, err := LoadAttacks(in.StateDir, in.Now)
	if err != nil {
		return nil, err
	}
	p := &PassRound{dir: in.StateDir, now: in.Now, in: in, attacks: a}
	if p.baselines, err = LoadBaselines(in.StateDir, in.Now); err != nil {
		p.baselines = &Baselines{Version: 1, Routes: map[string]*baseline{}}
		p.notice("回應大小基準檔無法讀取，這輪從空的基準開始：" + Printable(err.Error()))
	}
	cs, err := LoadCursors(in.StateDir)
	if err != nil {
		p.notice("讀取進度檔無法讀取，所有記錄檔這輪都從頭讀（first_run）：" + Printable(err.Error()))
	}
	p.cursors = cs
	dropped := map[string]string{}
	for _, d := range cs.Dropped {
		k, why, _ := strings.Cut(d, " (")
		dropped[k] = strings.TrimSuffix(why, ")")
	}
	if len(cs.Dropped) > 0 {
		p.notice(fmt.Sprintf("有 %d 個記錄檔的讀取進度無效，已從頭讀（first_run），期間的紀錄可能重複或缺漏：%s", len(cs.Dropped), Printable(strings.Join(cs.Dropped, "、"))))
	}
	p.dropped = dropped
	return p, nil
}

// Run reads and judges the round's sources, one after the other. Each
// source's cursor is kept only when its read is done; a round given up
// (Abandon) keeps the sources done and what they gave, and the source
// being read is read again from where it was by the next round.
func (p *PassRound) Run(ctx context.Context) {
	in, cs, dropped := p.in, p.cursors, p.dropped

	web := in.Sources.WebAccounts(in.Src)
	logs := in.Sources.WebLogs(in.Src)
	if !logs.Known() {
		p.notice("無法列出網站記錄檔（" + string(logs.Reason) + "），這輪沒有讀 web log")
	} else if logs.Status == hostenv.StatusPartial {
		p.notice("網站記錄檔只列出一部分（" + string(logs.Reason) + "）：" + Printable(logs.Detail))
	}
	units := in.Sources.AppUnits(in.Src)
	if units.Status == hostenv.StatusPartial {
		p.notice("應用程式 unit 只列出一部分（" + string(units.Reason) + "）：" + Printable(units.Detail))
	}
	trust := func(server string) TrustFunc { // a rotated file beside a log of server's
		return func(path string) hostenv.TrustResult { return hostenv.JudgeLog(in.Src, path, web.ForServer(server)) }
	}
	// start says a source is being read, false when the round was given up.
	start := func(key string) bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.current = key
		return !p.abandoned
	}

	// Error logs and application units first: their entries back this
	// round's attempts (L3, error log evidence).
	var events []ErrorEvent
	for _, ls := range logs.Value {
		if ls.Kind != "error" && ls.Kind != "php_error" {
			continue
		}
		ls := ls
		if !start(ls.Path) {
			return
		}
		var good, bad []string
		cur := cs.get(ls.Path)
		c, res, err := ReadLog(in.Src, ls.Path, cur, in.Budget, ReadOpts{Want: &ls, Trust: trust(ls.Server)}, func(l Line) {
			if l.Verified {
				good = append(good, string(l.Text))
			} else {
				bad = append(bad, string(l.Text))
			}
		})
		events = append(events, ErrorEvents(good, true, ls.Path, in.Loc)...)
		events = append(events, ErrorEvents(bad, false, ls.Path, in.Loc)...)
		p.read(ls.Path, ls.Kind, ls.Verified, c, res, nil, err)
	}
	if units.Known() {
		for _, u := range units.Value {
			key := JournalKey(u.Name)
			if !start(key) {
				return
			}
			c, res, err := ReadJournalUnit(ctx, in.Src, u, cs.get(key), in.Budget, web, func(e hostenv.JournalEntry, t JournalTrust) {
				if ev, ok := entryEvent(e, t.Verified); ok {
					events = append(events, ev)
				}
			})
			p.read(key, "journal", false, c, res, nil, err)
		}
	}

	m := NewMatcher(in.Sigs)
	j := NewJudge(in.Surface, in.Sigs)
	ev := Evidence{Baselines: p.baselines, Errors: events, CodeRoots: in.CodeRoots}
	for _, ls := range logs.Value {
		if ls.Kind != "access" {
			continue
		}
		ls := ls
		if !start(ls.Path) {
			return
		}
		custom := !knownFormats[strings.ToLower(ls.Format)]
		reason := ""
		if !ls.Verified {
			reason = "記錄檔未通過信任檢查（" + string(ls.Reason) + "），內容可能被竄改"
		}
		onRecord := func(rec AccessRecord, l Line) {
			o := Origin{Verified: l.Verified, Custom: custom}
			if !l.Verified {
				o.Reason = reason
				switch {
				case o.Reason != "":
				case ls.Journal != "":
					o.Reason = "這筆 journald 紀錄不是 nginx 的 worker 經 syslog 送出的（程式、帳號或傳送方式不符），可能是別的程序冒充"
				default:
					o.Reason = "這段紀錄來自未通過信任檢查的輪替檔"
				}
			}
			results := m.MatchRecord(rec)
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.abandoned {
				return
			}
			for _, mr := range results {
				g := j.Judge(mr)
				p.Round.Judged(g)
				for _, at := range j.Attempts(rec, o, mr, g) {
					Upgrade(&at, rec.Method, ev)
					p.attacks.Add(at, in.Now)
				}
				// The size baseline leaves out only a request a hit took to
				// L2: an unanchored or noise hit is an ordinary response
				// of the route (v0.4.1, n36).
				l2 := slices.ContainsFunc(g.Candidates, func(c Candidate) bool { return c.Level == LevelPayload })
				if !l2 && l.Verified && rec.Status >= 200 && rec.Status < 300 {
					for _, c := range g.Candidates {
						p.baselines.Observe(RouteKey(rec.Method, c.Route, ""), rec.Client, rec.Bytes, rec.Time)
					}
				}
			}
		}
		var c Cursor
		var res ReadResult
		var sigs Signals
		var err error
		if ls.Journal != "" {
			c, res, sigs, err = ScanJournalAccess(ctx, in.Src, ls, cs.get(ls.Path), dropped[ls.Path], in.Budget, onRecord)
		} else {
			c, res, sigs, err = ScanAccess(in.Src, ls, cs.get(ls.Path), dropped[ls.Path], in.Budget, trust(ls.Server), onRecord)
		}
		p.read(ls.Path, ls.Kind, ls.Verified, c, res, &sigs, err)
		p.mu.Lock()
		if !p.abandoned {
			p.signalNotices(ls.Path, sigs)
		}
		p.mu.Unlock()
	}
	p.mu.Lock()
	if !p.abandoned {
		p.attacks.PassTimeouts, p.current = 0, ""
	}
	p.mu.Unlock()
}

// Interrupt gives the round up because the patrol was told to stop
// (SIGTERM): as Abandon keeps what was finished, but it is no timeout and
// not counted as one.
func (p *PassRound) Interrupt() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.abandoned {
		return
	}
	p.abandoned = true
	p.Notices = append(p.Notices, fmt.Sprintf("這輪攻擊偵測被中止（巡檢收到停止要求，停在 %s），已讀完的記錄檔照常保存，沒讀完的下一輪接著讀", Printable(p.current)))
}

// Abandon gives the round up (its time ran out): the sources read so far
// and what they gave are kept, the one being read is read again from its
// cursor next round; said in the notices, louder after PassTimeoutsWarn
// in a row.
func (p *PassRound) Abandon(limit time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.abandoned {
		return
	}
	p.abandoned = true
	p.attacks.PassTimeouts++
	n := p.attacks.PassTimeouts
	msg := fmt.Sprintf("這輪攻擊偵測在 %s 內沒有讀完（停在 %s），已讀完的記錄檔照常判斷與累計，沒讀完的下一輪從原位置接著讀", limit, Printable(p.current))
	if n >= PassTimeoutsWarn {
		msg = fmt.Sprintf("攻擊偵測已連續 %d 輪沒有讀完（這輪停在 %s）：可能有記錄檔所在的掛載點卡住，或記錄檔大到讀不完，期間的攻擊可能沒被檢查，請到伺服器上確認", n, Printable(p.current))
	}
	p.Notices = append(p.Notices, msg)
}

// entryEvent is an application unit's journal entry as an error event:
// its time journald's, its frame the runtime's own location on its message
// (phpLocation, after journald's time-less message is given PHP's shape).
func entryEvent(e hostenv.JournalEntry, verified bool) (ErrorEvent, bool) {
	if e.Time.IsZero() || e.MessageMissing {
		return ErrorEvent{}, false
	}
	msg := hostenv.MaskSecrets(e.Message)
	ev := ErrorEvent{Time: e.Time, Verified: verified, From: JournalKey(e.Unit)}
	if m := phpLocation("[" + e.Time.UTC().Format("02-Jan-2006 15:04:05") + " UTC] " + strings.TrimPrefix(msg, "PHP message: ")); m != nil {
		if line, err := strconv.Atoi(m[2]); err == nil {
			ev.Frames = []Frame{{File: m[1], Line: line}}
		}
	}
	return ev, true
}

// read records one source's read and keeps its cursor.
func (p *PassRound) read(key, kind string, verified bool, c Cursor, res ReadResult, sigs *Signals, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.abandoned { // given up while this source was read: its cursor stays where it was
		return
	}
	if p.cursors.Sources == nil {
		p.cursors.Sources = map[string]Cursor{}
	}
	p.cursors.Sources[key] = c
	r := SourceRead{Key: key, Kind: kind, Verified: verified, Read: res, Signals: sigs}
	if err != nil {
		r.Err = err.Error()
	}
	p.Sources = append(p.Sources, r)
	if slices.Contains(res.Partial, ReadCursorStuck) {
		p.notice("讀取進度卡住（cursor_stuck）：" + Printable(key) + " 連續多輪讀取失敗，這段期間的紀錄沒有被檢查")
	}
}

// signalNotices says an access log's signs of tampering.
func (p *PassRound) signalNotices(key string, s Signals) {
	if s.Unparsed.Count >= NoticeUnparsedMin && s.Lines > 0 && s.Unparsed.Count*100 >= s.Lines*NoticeUnparsedShare {
		p.notice(fmt.Sprintf("%s 有 %d / %d 行無法依格式解析，可能是格式設定變了，也可能有人刻意寫入無法解析的行", Printable(key), s.Unparsed.Count, s.Lines))
	}
	var marks []string
	if s.Suspicious.Count > 0 {
		marks = append(marks, fmt.Sprintf("只能從行尾切開的可疑行 %d 行", s.Suspicious.Count))
	}
	if s.Ambiguous.Count > 0 {
		marks = append(marks, fmt.Sprintf("有多種解讀的行 %d 行", s.Ambiguous.Count))
	}
	if s.Cut.Count > 0 {
		marks = append(marks, fmt.Sprintf("超長被截斷的行 %d 行", s.Cut.Count))
	}
	if len(marks) > 0 {
		p.notice(Printable(key) + "：" + strings.Join(marks, "、") + "（這些行仍照常比對，告警會標記）")
	}
}

func (p *PassRound) notice(s string) { p.Notices = append(p.Notices, s) }

func (p *PassRound) locked(f func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f()
}

// Due are the groups to notify now (Attacks.Due).
func (p *PassRound) Due() (out []*Group) {
	p.locked(func() { out = p.attacks.Due(p.now) })
	return out
}

// Notified says g was sent.
func (p *PassRound) Notified(g *Group) { p.locked(func() { p.attacks.Notified(g, p.now) }) }

// Attacks is the round's state, for the report.
func (p *PassRound) Attacks() *Attacks { return p.attacks }

// NoticeText is what to send apart from the groups' alerts: the state's
// (NoticeText), the baselines' note, and the round's notices. "" when
// there is nothing.
func (p *PassRound) NoticeText() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var b strings.Builder
	b.WriteString(NoticeText(p.attacks))
	if p.baselines.Note != "" {
		b.WriteString("【Shentu 攻擊偵測】回應大小基準檔異常：" + Printable(p.baselines.Note) + "\n")
	}
	for _, n := range p.Notices {
		b.WriteString("【Shentu 攻擊偵測】" + n + "\n")
	}
	return b.String()
}

// NoticesSent says NoticeText was sent.
func (p *PassRound) NoticesSent() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.attacks.NoticesSent()
	p.baselines.Note, p.Notices = "", nil
}

// Save writes the cursors, the baselines and attacks.json.
func (p *PassRound) Save() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	cerr := p.cursors.Save(p.dir)
	berr := p.baselines.Save(p.dir, p.now)
	aerr := p.attacks.Save(p.dir, p.now)
	return errors.Join(cerr, berr, aerr)
}

// Close releases attacks.lock.
func (p *PassRound) Close() error { return p.attacks.Close() }

// get is key's cursor, nil for none (a first run).
func (c *Cursors) get(key string) *Cursor {
	if cur, ok := c.Sources[key]; ok {
		return &cur
	}
	return nil
}
