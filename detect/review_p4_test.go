package detect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/rules/engine"
)

// Review 1 of #90 (P4): each B and N item's case, neutral markers only.

// B-1: X-Forwarded-For is only ever a list of addresses.
func TestValidXFF(t *testing.T) {
	for x, want := range map[string]bool{
		"192.0.2.1": true, "192.0.2.1, 2001:db8::1": true, "marker": false, "0.0.0.0/0": false,
		"192.0.2.1\n來源可信度：已驗證": false, "192.0.2.1,": false, "fe80::1%eth0": false, "fe80::1%marker x": false,
	} {
		if got := validXFF(x); got != want {
			t.Errorf("%q: %v, want %v", x, got, want)
		}
	}
}

// B-2: an attempt whose source is not believed neither counts nor is
// kept for a campaign; a flood of sources trying one each goes first.
func TestCampaignVerifiedOnly(t *testing.T) {
	a := newAttacks()
	for _, e := range []string{"e1", "e2"} {
		x := att("192.0.2.1", e, LevelPayload, t0)
		x.Verified = false
		a.Add(x, t0)
	}
	if g := a.Add(att("192.0.2.1", "e3", LevelPayload, t0), t0); g.Campaign || g.Severity != "high" {
		t.Errorf("unverified tries raised a verified one: %+v", g)
	}
	if len(a.IPs) != 1 || len(a.IPs["192.0.2.1"].Entries) != 1 {
		t.Errorf("unverified tries kept: %+v", a.IPs["192.0.2.1"])
	}
	b := newAttacks()
	b.Add(att("192.0.2.9", "e1", LevelPayload, t0), t0)
	b.Add(att("192.0.2.9", "e2", LevelPayload, t0), t0)
	for i := 0; i < MaxIPIndex+5; i++ {
		b.Add(att(fmt.Sprintf("10.%d.%d.1", i/256, i%256), "e1", LevelPayload, t0.Add(time.Duration(i+1)*time.Second)), t0)
	}
	if r := b.IPs["192.0.2.9"]; r == nil || len(r.Entries) != 2 {
		t.Errorf("a source near a campaign pushed out by a flood of one-try sources: %+v", r)
	}
}

// N-2: IPv6 sources are counted by /64.
func TestCampaignIPv6Network(t *testing.T) {
	a := newAttacks()
	a.Add(att("2001:db8:1:2::1", "e1", LevelPayload, t0), t0)
	a.Add(att("2001:db8:1:2::2", "e2", LevelPayload, t0), t0)
	if g := a.Add(att("2001:db8:1:2::3", "e3", LevelPayload, t0), t0); !g.Campaign {
		t.Errorf("one /64 trying three: %+v", g)
	}
}

// N-3: believed and unbelieved attempts are separate groups.
func TestGroupsByBelief(t *testing.T) {
	a := newAttacks()
	a.Add(att("192.0.2.1", "e1", LevelPayload, t0), t0)
	u := att("192.0.2.2", "e1", LevelPayload, t0)
	u.Verified = false
	a.Add(u, t0)
	v, n := a.Groups["192.0.2.0/24|e1|L2|v"], a.Groups["192.0.2.0/24|e1|L2|u"]
	if v == nil || n == nil || v.Unverified || !n.Unverified {
		t.Errorf("groups %+v", a.Groups)
	}
}

// B-4, N-1, N-9: a pending group evicted is merged into an overflow group
// (notified), counted across a save, and said apart; so is a bad file.
func TestOverflowAndNotices(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadAttacks(dir, t0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxGroups+10; i++ {
		a.Add(att(fmt.Sprintf("2001:db8:%x::1", i+1), "e1", LevelPayload, t0.Add(time.Duration(i)*time.Second)), t0)
	}
	if err := a.Save(dir, t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	a.Close()
	b, err := LoadAttacks(dir, t0.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.DroppedPending != 10 || len(b.Groups) != MaxGroups {
		t.Fatalf("after load: dropped %d, %d groups", b.DroppedPending, len(b.Groups))
	}
	var overflow *Group
	for _, g := range b.Due(t0.Add(2 * time.Hour)) {
		if g.Prefix == PrefixOverflow {
			overflow = g
		}
	}
	if overflow == nil || overflow.Merged != 10 || overflow.Count != 10 || overflow.Since != 10 {
		t.Fatalf("overflow group %+v", overflow)
	}
	if txt := AlertText(overflow, nil); !strings.Contains(txt, "溢出彙總：10 組") || strings.Contains(txt, "只會針對單一 IP") || !strings.Contains(txt, "溢出彙總組不提供封鎖") {
		t.Errorf("overflow alert (never a block, N-R2-2):\n%s", txt)
	}
	if txt := NoticeText(b); !strings.Contains(txt, "有 10 組尚未推播") {
		t.Errorf("notice: %q", txt)
	}
	b.NoticesSent()
	if NoticeText(b) != "" {
		t.Error("notice after it was sent")
	}
}

// N-4: a time past the clock (the clock set back) does not mute a group.
func TestClockSetBack(t *testing.T) {
	a := newAttacks()
	g := a.Add(att("192.0.2.1", "e1", LevelPayload, t0.Add(48*time.Hour)), t0)
	a.Notified(g, t0.Add(48*time.Hour))
	a.Add(att("192.0.2.1", "e1", LevelPayload, t0), t0)
	due := a.Due(t0.Add(time.Hour))
	if len(due) != 1 || !due[0].ClockSkew {
		t.Fatalf("notified in the future: %+v", due)
	}
	a.prune(t0.Add(time.Hour))
	if !g.Last.Equal(t0.Add(time.Hour)) {
		t.Errorf("last seen in the future kept: %v", g.Last)
	}
	if txt := AlertText(due[0], nil); !strings.Contains(txt, "時鐘異常") {
		t.Errorf("alert:\n%s", txt)
	}
}

// N-5, N-6: a file holding null entries does not crash, and is said; a
// link or a file others may write is refused.
func TestStateFileChecks(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, AttacksFile)
	if err := os.WriteFile(p, []byte(`{"version":1,"groups":{"k":null,"x":{"key":"y"}},"ips":{"192.0.2.1":{"last":"2026-11-16T10:00:00Z"},"192.0.2.2":null}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := LoadAttacks(dir, t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Groups) != 0 || len(a.IPs) != 0 || !strings.Contains(a.Note, "4 entries") {
		t.Errorf("%+v note %q", a, a.Note)
	}
	a.Add(att("192.0.2.1", "e1", LevelPayload, t0), t0) // no nil map written
	a.Close()
	if err := os.WriteFile(filepath.Join(dir, BaselinesFile), []byte(`{"version":1,"routes":{"GET /m":null}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := LoadBaselines(dir, t0); err != nil || len(b.Routes) != 0 || b.Note == "" {
		t.Errorf("baselines: %v %+v", err, b)
	}
	other := t.TempDir()
	target := filepath.Join(other, "elsewhere.json")
	if err := os.WriteFile(target, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := t.TempDir()
	if err := os.Symlink(target, filepath.Join(link, AttacksFile)); err != nil {
		t.Skip(err)
	}
	if a, err := LoadAttacks(link, t0); err == nil {
		a.Close()
		t.Error("a link read")
	}
	wide := t.TempDir()
	if err := os.WriteFile(filepath.Join(wide, AttacksFile), []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Chmod(filepath.Join(wide, AttacksFile), 0o666)
	if a, err := LoadAttacks(wide, t0); err == nil {
		a.Close()
		t.Error("a file others may write read")
	}
}

// N-7: a second load waits for the first to close.
func TestAttacksLock(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadAttacks(dir, t0)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan *Attacks)
	go func() {
		b, _ := LoadAttacks(dir, t0)
		got <- b
	}()
	select {
	case <-got:
		t.Fatal("loaded while another held the lock")
	case <-time.After(200 * time.Millisecond):
	}
	a.Close()
	select {
	case b := <-got:
		b.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("not loaded after the lock was released")
	}
}

// N-8: Unknown's threshold slides: 19 at a window's end and 19 at the next
// one's start are 38 within 24 hours.
func TestUnknownSlidingWindow(t *testing.T) {
	a := newAttacks()
	a.Add(att("192.0.2.1", "sink", LevelUnknown, t0), t0) // opens a fixed window: 1 + 18 in it, 19 after it
	for i := 0; i < UnknownNotifyAt-2; i++ {
		a.Add(att("192.0.2.1", "sink", LevelUnknown, t0.Add(23*time.Hour+time.Duration(i)*time.Minute)), t0)
	}
	for i := 0; i < UnknownNotifyAt-1; i++ {
		a.Add(att("192.0.2.1", "sink", LevelUnknown, t0.Add(25*time.Hour+time.Duration(i)*time.Minute)), t0)
	}
	if due := a.Due(t0.Add(26 * time.Hour)); len(due) != 1 {
		t.Errorf("37 within 24 hours not notified: %d due", len(due))
	}
	b := newAttacks()
	for i := 0; i < UnknownNotifyAt; i++ {
		b.Add(att("192.0.2.1", "sink", LevelUnknown, t0.Add(time.Duration(i)*2*time.Hour)), t0)
	}
	if due := b.Due(t0.Add(40 * time.Hour)); len(due) != 0 {
		t.Errorf("20 over 38 hours notified")
	}
}

// B-3: PHP's location only where it certainly ends the message.
func TestPHPLocationCertain(t *testing.T) {
	forged := " in /srv/app/x.php on line 12"
	for name, l := range map[string]string{
		"apache, referer in the message, none after": "[Mon Nov 16 10:11:15.1 2026] [php:error] [pid 9] PHP Warning:  marker" + forged + ", referer: z in /srv/app/real.php on line 5",
		"apache, two referers":                       "[Mon Nov 16 10:11:15.1 2026] [php:error] [pid 9] PHP Warning:  marker" + forged + ", referer: z in /srv/app/real.php on line 5, referer: q",
		"nginx, the end twice":                       `2026/11/16 10:11:16 [error] 7#0: *7 FastCGI sent in stderr: "PHP message: PHP Warning:  marker` + forged + `" while reading , client: z in /srv/app/real.php on line 5" while reading response header from upstream, client: 192.0.2.1`,
	} {
		if m := phpLocation(l); m != nil && m[1] == "/srv/app/x.php" {
			t.Errorf("%s: forged location taken: %v", name, m)
		}
	}
	for name, c := range map[string]struct {
		line, file string
	}{
		"apache, a referer":  {"[Mon Nov 16 10:11:15.1 2026] [php:error] [pid 9] PHP Warning:  marker in /srv/app/real.php on line 5, referer: /srv/app/x.php:12", "/srv/app/real.php"},
		"apache, no referer": {"[Mon Nov 16 10:11:15.1 2026] [php:error] [pid 9] PHP Warning:  marker in /srv/app/real.php on line 5", "/srv/app/real.php"},
		"php's own log":      {"[16-Nov-2026 10:11:14 UTC] PHP Warning:  marker" + forged + " in /srv/app/real.php on line 5", "/srv/app/real.php"},
		"nginx, one end":     {`2026/11/16 10:11:16 [error] 7#0: *7 FastCGI sent in stderr: "PHP message: PHP Warning:  marker in /srv/app/real.php on line 5" while reading response header from upstream, client: 192.0.2.1`, "/srv/app/real.php"},
	} {
		if m := phpLocation(c.line); m == nil || m[1] != c.file {
			t.Errorf("%s: %v, want %s", name, m, c.file)
		}
	}
}

// Decision 2 of review 1, N-R2-1 of review 2: L3 is at most high unless
// both kinds of evidence back it and the entry is KEV or it is a
// campaign (the error log counts half).
func TestL3BothEvidence(t *testing.T) {
	ev := Evidence{Baselines: steadyBaseline("GET /marker/:id", 30),
		Errors: []ErrorEvent{{Time: t0.Add(10 * time.Second), Frames: []Frame{{"/srv/www/app/x.php", 12}}, Verified: true}}}
	a := l2("app/x.php", 12, t0)
	a.Bytes, a.Severe = 9000, true
	if !Upgrade(&a, "GET", ev) || !a.SizeEvidence || !a.ErrorEvidence || a.Severity != "high" {
		t.Errorf("both kinds, critical entry, not KEV: %+v", a)
	}
	if a.KEV, a.ReqLogged = true, true; a.SeverityWith(false) != "critical" || (Attempt{Level: LevelSuccess, Verified: true, SizeEvidence: true, ReqLogged: true, ErrorEvidence: true}).SeverityWith(true) != "critical" {
		t.Errorf("both kinds and KEV, or a campaign: %s", a.SeverityWith(false))
	}
	a = l2("app/x.php", 12, t0)
	a.Severe, a.KEV = true, true
	if !Upgrade(&a, "GET", ev) || a.SizeEvidence || a.Severity != "high" {
		t.Errorf("the error log alone, KEV: %+v", a)
	}
	// N-R2-1: one request making both: a POST whose length is not logged
	// (its body may be echoed back) is no size evidence.
	evPost := Evidence{Baselines: steadyBaseline("POST /marker/:id", 30), Errors: ev.Errors}
	a = l2("app/x.php", 12, t0)
	a.Bytes, a.KEV, a.ReqKnown = 9000, true, false
	if !Upgrade(&a, "POST", evPost) || a.SizeEvidence || a.Severity != "high" {
		t.Errorf("POST, length not logged: %+v", a)
	}
	a = l2("app/x.php", 12, t0)
	a.Bytes, a.KEV, a.ReqLen, a.ReqLogged = 9000, true, 100, true // logged: known
	if !Upgrade(&a, "POST", evPost) || !a.SizeEvidence || a.Severity != "critical" {
		t.Errorf("POST, length logged, both kinds, KEV: %+v", a)
	}
	ss := loadSigs(t, markerSigs)
	j := NewJudge(Build([]CodeSink{{Rule: "js-sqli", CWE: "CWE-89", Severity: "warning", Path: "app/a.js", Line: 7,
		Routes: []engine.RouteRef{{Model: "m", Framework: "express", Method: "all", Pattern: "/marker/ping", File: "app/a.js", Line: 7}}}}, nil), ss)
	m := NewMatcher(ss)
	post := attemptsOf(j, m, AccessRecord{Client: "192.0.2.1", Method: "POST", Path: "/marker/ping", Query: "q=marker-one", Status: 200, Bytes: 9000}, Origin{Verified: true})
	logged := attemptsOf(j, m, AccessRecord{Client: "192.0.2.1", Method: "POST", Path: "/marker/ping", Query: "q=marker-one", Status: 200, Bytes: 9000, ReqLength: 8800}, Origin{Verified: true})
	if post[0].ReqKnown || !logged[0].ReqKnown || logged[0].ReqLen != 8800 {
		t.Errorf("request length: %+v %+v", post[0], logged[0])
	}
	// S-5: error log evidence needs the access log verified.
	a = l2("app/x.php", 12, t0)
	a.LogVerified = false
	if Upgrade(&a, "GET", ev) {
		t.Errorf("raised from an unverified access log: %+v", a)
	}
}

// N-11: a response echoing the request back is not larger for it.
func TestUpgradeTakesOffRequest(t *testing.T) {
	ev := Evidence{Baselines: steadyBaseline("GET /marker/:id", 30)}
	a := l2("app/x.php", 12, t0)
	a.Bytes, a.ReqLen = 9000, 8500
	if Upgrade(&a, "GET", ev) {
		t.Errorf("an echoed request taken for a larger response: %+v", a)
	}
}

// N-12, N-13: one source gives a route at most PerSourceDay sizes a day;
// no route, no baseline; the route with the fewest sizes goes first.
func TestBaselineBounds(t *testing.T) {
	b := &Baselines{Version: 1, Routes: map[string]*baseline{}}
	for i := 0; i < 50; i++ {
		b.Observe("GET /m", "192.0.2.1", 50000, t0.Add(time.Duration(i)*time.Minute))
	}
	if n := len(b.Routes["GET /m"].Sizes); n != PerSourceDay {
		t.Errorf("one source gave %d sizes in a day", n)
	}
	b.Observe("GET /m", "192.0.2.1", 50000, t0.Add(25*time.Hour))
	if n := len(b.Routes["GET /m"].Sizes); n != PerSourceDay+1 {
		t.Errorf("next day: %d sizes", n)
	}
	b.Observe("", "192.0.2.1", 1, t0)
	if _, ok := b.Routes[""]; ok {
		t.Error("a baseline with no route")
	}
	c := steadyBaseline("GET /full", 30)
	c.Observe("GET /thin", "192.0.2.1", 1, t0.Add(time.Hour))
	c.evict(1)
	if _, ok := c.Routes["GET /full"]; !ok {
		t.Errorf("the route with more sizes pushed out: %v", c.Routes)
	}
}

// S-3: a one-segment sink file matches no directory's; with code roots,
// the file must be the root's exactly.
func TestSinkFile(t *testing.T) {
	for _, c := range []struct {
		logged, sink string
		roots        []string
		want         bool
	}{
		{"/srv/app/x.php", "x.php", nil, false},
		{"/srv/www/app/x.php", "app/x.php", nil, true},
		{"/srv/www/app/x.php", "app/x.php", []string{"/srv/www"}, true},
		{"/srv/other/app/x.php", "app/x.php", []string{"/srv/www"}, false},
		{"/srv/www/x.php", "x.php", []string{"/srv/www"}, true},
		{"/srv/www/x.php", "/srv/www/x.php", nil, true},
	} {
		if got := sinkFile(c.logged, c.sink, c.roots); got != c.want {
			t.Errorf("%+v: %v", c, got)
		}
	}
}

// N-14, N-15, N-16: more sensitive names, path parameters, and nothing
// that could start a line.
func TestSampleMasksMore(t *testing.T) {
	kv := func(k string) string { return k + "=v-" + k }
	names := []string{"PHPSESSID", "pass", "pw", "pwd", "auth", "sid", "code", "sig", "cvv", "private_key", "apikey", "api_key", "jwt", "otp", "pin", "ssn", "credential", "p%77d", "api%6Bey"}
	var q []string
	for _, n := range names {
		q = append(q, kv(n))
	}
	s := Sample(AccessRecord{Method: "GET", Path: "/a;jsessionid=v-path/b", Query: strings.Join(q, "&")})
	for _, n := range append(names, "path") {
		if strings.Contains(s, "v-"+n) {
			t.Errorf("%s shown: %s", n, s)
		}
	}
	for _, in := range []string{"/m\nfake line", "/m\r", "/m x", "/m‮x", "/m\x85x", "/m\x7f"} {
		s := Sample(AccessRecord{Method: "GET", Path: in})
		if strings.ContainsFunc(s, unprintable) {
			t.Errorf("%q: %q", in, s)
		}
	}
	j, m := attemptJudge(t)
	rec := AccessRecord{Client: "192.0.2.1\nfake", Method: "GET", Path: "/marker/ping", Query: "q=marker-one"}
	as := attemptsOf(j, m, rec, Origin{Verified: true})
	a := newAttacks()
	g := a.Add(as[0], t0)
	txt := AlertText(g, nil)
	if strings.Contains(txt, "\nfake") {
		t.Errorf("a line made by the request:\n%s", txt)
	}
}

// S-2: the report masks addresses in samples.
func TestReportMasksSamples(t *testing.T) {
	a := newAttacks()
	x := att("192.0.2.1", "e1", LevelPayload, t0)
	x.Sample = "GET /marker?u=http://198.51.100.77/x"
	g := a.Add(x, t0)
	if txt := ReportText(g, nil); strings.Contains(txt, "198.51.100.77") || !strings.Contains(txt, "198.51.x.x") {
		t.Errorf("report:\n%s", txt)
	}
}

// Review 2 of #90 (S): a zone after % is no address for the log's client
// either; short sensitive words only as whole words; a cut sample does
// not end in half an address.
func TestReview2Small(t *testing.T) {
	var r AccessRecord
	if r.set("client", "fe80::1%eth0") || !r.set("client", "2001:db8::1") {
		t.Errorf("client with a zone taken, or one without refused: %q", r.Client)
	}
	for _, n := range []string{"keyword", "shipping", "success", "author", "side", "page", "q"} {
		if s := Sample(AccessRecord{Method: "GET", Path: "/m", Query: n + "=marker-v"}); !strings.Contains(s, "marker-v") {
			t.Errorf("%s masked: %s", n, s)
		}
	}
	// Security review of review 2's fix: a short word ending a word, or
	// after a camelCase boundary, still masks.
	for _, n := range []string{"user_key", "pin", "card-no", "x[pw]", "auth.code", "PHPSESSID", "access_token", "userpass", "authkey", "accessKey", "x_authcode", "creditCardNumber", "zipPin"} {
		if s := Sample(AccessRecord{Method: "GET", Path: "/m", Query: n + "=marker-v"}); strings.Contains(s, "marker-v") {
			t.Errorf("%s shown: %s", n, s)
		}
	}
	long := Sample(AccessRecord{Method: "GET", Path: "/" + strings.Repeat("m", MaxSample-12) + "/198.51.100.77/x"})
	if strings.Contains(long, "198.51") || len(long) > MaxSample {
		t.Errorf("a cut sample ends in part of an address: %q", long[len(long)-20:])
	}
}

// P4 close-out: size evidence helps to critical only against a request
// length the log wrote; more secret names; escapes are no word
// boundary; an unverified overflow group cannot be unblocked from
// Telegram either.
func TestP4CloseOut(t *testing.T) {
	ss := loadSigs(t, markerSigs)
	j := NewJudge(Build([]CodeSink{{Rule: "js-sqli", CWE: "CWE-89", Severity: "warning", Path: "app/x.php", Line: 12,
		Routes: []engine.RouteRef{{Model: "m", Framework: "express", Method: "get", Pattern: "/marker/:id", File: "app/x.php", Line: 12}}}}, nil), ss)
	m := NewMatcher(ss)
	q := "q=marker-one&pad=" + strings.Repeat("z", 8000)
	rec := AccessRecord{Client: "192.0.2.1", Time: t0, Method: "GET", Path: "/marker/5", Query: q, Status: 200, Bytes: int64(3*len(q) + 1000)}
	as := attemptsOf(j, m, rec, Origin{Verified: true})
	if len(as) == 0 {
		t.Fatal("no attempt")
	}
	a := as[0]
	a.KEV = true
	ev := Evidence{Baselines: steadyBaseline("GET /marker/:id", 30),
		Errors: []ErrorEvent{{Time: t0.Add(10 * time.Second), Frames: []Frame{{"/srv/www/app/x.php", 12}}, Verified: true}}}
	if !Upgrade(&a, "GET", ev) || !a.SizeEvidence || !a.ErrorEvidence || a.ReqLogged || a.Severity != "high" {
		t.Errorf("an 8000B query echoed three times, the error log, KEV, no request_length: %+v", a)
	}
	for _, n := range []string{"ticket", "SAMLResponse", "user_creds", "x-hmac", "x_sess", "userSess"} {
		if s := Sample(AccessRecord{Method: "GET", Path: "/m", Query: n + "=marker-v"}); strings.Contains(s, "marker-v") {
			t.Errorf("%s shown: %s", n, s)
		}
	}
	if got := camelSplit("a%2Fb"); got != "a%2Fb" {
		t.Errorf("camelSplit(a%%2Fb) = %q", got)
	}
	if s := Sample(AccessRecord{Method: "GET", Path: "/m", Query: "x%2Dkey=marker-v&a%2Fb=marker-w"}); strings.Contains(s, "marker-v") || !strings.Contains(s, "marker-w") {
		t.Errorf("escaped names: %s", s)
	}
	g := &Group{Key: "o", Prefix: PrefixOverflow, Level: LevelPayload, Severity: "medium", Unverified: true, IPs: []string{"192.0.2.1"}, IPsSeen: 1}
	if txt := AlertText(g, nil); !strings.Contains(txt, NoTelegramUnblock) || !strings.Contains(txt, "溢出彙總組不提供封鎖") {
		t.Errorf("unverified overflow alert:\n%s", txt)
	}
}

var _ = engine.RouteRef{}

// P5 part 4: an installed WordPress plugin is matched by a signature
// written for its slug and version range, CVE or not.
func TestInstalledPlugins(t *testing.T) {
	ss := loadSigs(t, `
[[signature]]
id = "wp-marker"
title = "a plugin's"
class = "sqli"
cves = ["CVE-2099-0101"]
source = "shentu"
license = "Apache-2.0"
[[signature.applies_to]]
ecosystem = "WordPress"
package = "marker-plugin"
versions = "<1.3"
[[signature.match]]
part = "any_param"
contains = ["marker-one"]
`)
	judge := func(v string) Judgment {
		s := Build(nil, nil, InstalledPackage{Source: "/srv/www", Ecosystem: "WordPress", Package: "marker-plugin", Version: v})
		return NewJudge(s, ss).Judge(NewMatcher(ss).Match(Normalize(AccessRecord{Method: "GET", Path: "/", Query: "q=marker-one"})))
	}
	if g := judge("1.2.3"); len(g.Candidates) != 1 || g.Candidates[0].Level != LevelPayload || g.Candidates[0].VersionUnknown {
		t.Errorf("1.2.3 in <1.3: %+v", g)
	}
	if g := judge("1.3.0"); len(g.Candidates) != 0 || len(g.Noise) != 1 {
		t.Errorf("1.3.0: %+v", g)
	}
	if g := judge("1.2-beta"); len(g.Candidates) != 1 || !g.Candidates[0].VersionUnknown {
		t.Errorf("a suffix, unknown: %+v", g)
	}
	if g := judge(""); len(g.Candidates) != 1 || !g.Candidates[0].VersionUnknown {
		t.Errorf("no version header: %+v", g)
	}
	s := Build(nil, nil, InstalledPackage{Source: "/srv/www", Ecosystem: "WordPress", Package: "other", Version: "1.0"})
	if g := NewJudge(s, ss).Judge(NewMatcher(ss).Match(Normalize(AccessRecord{Method: "GET", Path: "/", Query: "q=marker-one"}))); len(g.Candidates) != 0 {
		t.Errorf("another plugin: %+v", g)
	}
}

// P5 part 5: an OS package's advisory (Debian:12) is found by a signature
// written for Debian, its range compared in dpkg's order.
func TestOSPackageEntries(t *testing.T) {
	ss := loadSigs(t, `
[[signature]]
id = "deb-marker"
title = "an OS package's"
class = "path"
cves = ["CVE-2099-0200"]
source = "shentu"
license = "Apache-2.0"
[[signature.applies_to]]
ecosystem = "Debian"
package = "marker-httpd"
versions = "<2.4.62-1~deb12u1"
[[signature.match]]
part = "any_param"
contains = ["marker-one"]
`)
	judge := func(v string) Judgment {
		s := Build(nil, []PackageVuln{{Source: "os", Ecosystem: "Debian:12", Package: "marker-httpd", Version: v, ID: "DSA-0000-1", CVE: "CVE-2099-0200"}})
		return NewJudge(s, ss).Judge(NewMatcher(ss).Match(Normalize(AccessRecord{Method: "GET", Path: "/", Query: "q=marker-one"})))
	}
	if g := judge("2.4.61-1~deb12u1"); len(g.Candidates) != 1 || g.Candidates[0].Level != LevelPayload || g.Candidates[0].VersionUnknown {
		t.Errorf("in range: %+v", g)
	}
	// Review 2 of #91 (N-B2): OSV found it affected; the base's range does
	// not overrule that: a candidate, version unknown.
	if g := judge("2.4.62-1~deb12u1"); len(g.Candidates) != 1 || !g.Candidates[0].VersionUnknown {
		t.Errorf("out of a base range: %+v", g)
	}
	if g := judge("2.4.62-1~deb12u0"); len(g.Candidates) != 1 {
		t.Errorf("~deb12u0 before ~deb12u1: %+v", g)
	}
}

// Review 2 of #91 (N-B1, N-B2): an OS advisory named DSA- or DEBIAN-CVE-
// is found by a CVE signature through its CVEs; a release-specific range
// for another release does not apply.
func TestOSEntriesReview2(t *testing.T) {
	ss := loadSigs(t, `
[[signature]]
id = "deb11-marker"
title = "for Debian 11"
class = "path"
cves = ["CVE-2099-0201"]
source = "shentu"
license = "Apache-2.0"
[[signature.applies_to]]
ecosystem = "Debian:11"
package = "marker-httpd"
versions = "<2.4.62-1~deb11u1"
[[signature.match]]
part = "any_param"
contains = ["marker-two"]
`)
	s := Build(nil, []PackageVuln{{Source: "os", Ecosystem: "Debian:12", Package: "marker-httpd", Version: "2.4.62-1~deb12u1", ID: "DSA-9999-1", CVEs: []string{"CVE-2099-0201"}, CVE: "CVE-2099-0201"}})
	g := NewJudge(s, ss).Judge(NewMatcher(ss).Match(Normalize(AccessRecord{Method: "GET", Path: "/", Query: "q=marker-two"})))
	if len(g.Candidates) != 1 || !g.Candidates[0].VersionUnknown {
		t.Errorf("Debian:11's range on a Debian:12 entry: %+v", g)
	}
	if sameEcosystem("Debian:11", "Debian:12") || !sameEcosystem("Debian", "Debian:12") || !sameEcosystem("debian:12", "Debian:12") {
		t.Error("sameEcosystem")
	}
}
