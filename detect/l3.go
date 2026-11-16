package detect

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nt-neil/shentu/hostenv"
	"github.com/nt-neil/shentu/rules/engine"
)

// L3, success likely (plan 0743f0, P4 part 3): an L2 attempt whose
// response stands out from its route's usual size, or that an error log
// ties to the sink's own file and line within ErrorWindow. Evidence from a
// log that is not verified never raises it.
const (
	BaselinesFile = "baselines.json"
	BaselineTTL   = 14 * 24 * time.Hour // a route not seen this long is dropped
	BaselineKeep  = 64                  // sizes kept per route, the latest
	MaxBaselines  = 1024
	MinBaseline   = 20 // fewer sizes than this: size says nothing
	// An error log entry backs an attempt from ErrorBefore before it (the
	// clocks of two logs differ a little) to ErrorWindow after it.
	ErrorWindow = 120 * time.Second
	ErrorBefore = 5 * time.Second
	// SizeFloor: a response this close to the median never stands out,
	// however steady the route.
	SizeFloor = 512
)

// Baselines are each route's response sizes, kept across passes in
// state_dir/baselines.json (a small site's route rarely sees MinBaseline
// requests in one pass). Only requests with no hit, a 2xx status and a
// verified log are observed: an attacker shifts the median only with
// many ordinary requests, and the median and MAD resist a few odd ones.
type Baselines struct {
	Version int                  `json:"version"`
	Routes  map[string]*baseline `json:"routes"`
	Note    string               `json:"-"` // why it started empty (a file that did not parse, set aside)
}

type baseline struct {
	Sizes []int64   `json:"sizes"` // the latest BaselineKeep, oldest first
	Last  time.Time `json:"last"`
	// Day and Took: how many sizes each source gave on Day (a UTC date),
	// at most PerSourceDay each: one source cannot fill the baseline.
	Day  string         `json:"day,omitempty"`
	Took map[string]int `json:"took,omitempty"`
}

// PerSourceDay bounds the sizes one source (an IPv4 address, an IPv6
// /64) gives a route's baseline in a day.
const PerSourceDay = 4

// RouteKey is the baseline's key for an attempt or a request: the method
// (one of the usual ones, HEAD as GET, any other as OTHER) and the code
// sink's route pattern, as the surface gives it: only routes of the
// surface have a baseline, so requests cannot make new ones, and no path
// as sent (which may hold a token) is kept. "" for none: a package's
// vulnerability has no route, so no size evidence.
func RouteKey(method string, route *engine.RouteRef, routedPath string) string {
	if route == nil || route.Pattern == "" {
		return ""
	}
	m := strings.ToUpper(method)
	switch m {
	case "HEAD":
		m = "GET"
	case "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
	default:
		m = "OTHER"
	}
	return m + " " + route.Pattern
}

// LoadBaselines reads dir's baselines.json as LoadAttacks reads its file
// (no link, ours, bounded); none is empty; one that does not parse is set
// aside, and routes that do not hold together dropped, said in Note.
func LoadBaselines(dir string, now time.Time) (*Baselines, error) {
	b := &Baselines{Version: 1, Routes: map[string]*baseline{}}
	var got Baselines
	note, err := readState(dir, BaselinesFile, &got, now)
	if err != nil {
		return nil, err
	}
	b.Note = note
	dropped := 0
	for k, r := range got.Routes {
		if r == nil || k == "" {
			dropped++
			continue
		}
		b.Routes[k] = r
	}
	if dropped > 0 {
		b.Note = join(b.Note, fmt.Sprintf("baselines.json held %d routes that did not hold together; they were dropped", dropped))
	}
	return b, nil
}

// Save writes the baselines to dir as attacks.json is written: routes not
// seen in BaselineTTL dropped, at most MaxBaselines (least recently seen
// go).
func (b *Baselines) Save(dir string, now time.Time) error {
	for k, r := range b.Routes {
		if now.Sub(r.Last) > BaselineTTL {
			delete(b.Routes, k)
		}
	}
	b.evict(MaxBaselines)
	b.Version = 1
	return saveJSON(dir, BaselinesFile, b)
}

func (b *Baselines) evict(n int) {
	if len(b.Routes) <= n {
		return
	}
	keys := make([]string, 0, len(b.Routes))
	for k := range b.Routes {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { // the ones with the fewest sizes go first, then the least recently seen
		x, y := b.Routes[keys[i]], b.Routes[keys[j]]
		if len(x.Sizes) != len(y.Sizes) {
			return len(x.Sizes) > len(y.Sizes)
		}
		if !x.Last.Equal(y.Last) {
			return x.Last.After(y.Last)
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys[n:] {
		delete(b.Routes, k)
	}
}

// Observe adds an ordinary response's size to key's baseline, from ip
// (at most PerSourceDay a day per source). The caller observes only
// requests with no hit, a 2xx status, from a verified log. A "" key (no
// route) is not kept.
func (b *Baselines) Observe(key, ip string, size int64, at time.Time) {
	if key == "" {
		return
	}
	r := b.Routes[key]
	if r == nil {
		if len(b.Routes) >= MaxBaselines+MaxBaselines/4 {
			b.evict(MaxBaselines - 1)
		}
		r = &baseline{}
		b.Routes[key] = r
	}
	if day := at.UTC().Format(time.DateOnly); r.Day != day {
		r.Day, r.Took = day, map[string]int{}
	}
	if r.Took == nil {
		r.Took = map[string]int{}
	}
	src := campaignSource(ip)
	if r.Took[src] >= PerSourceDay || len(r.Took) >= 4*BaselineKeep && r.Took[src] == 0 {
		return
	}
	r.Took[src]++
	r.Sizes = append(r.Sizes, size)
	if len(r.Sizes) > BaselineKeep {
		r.Sizes = r.Sizes[len(r.Sizes)-BaselineKeep:]
	}
	if at.After(r.Last) {
		r.Last = at
	}
}

// Deviates says whether size stands out above key's baseline: larger
// than the median by more than three scaled MADs, half the median and
// SizeFloor (a smaller response is an error page as often as anything:
// not taken). known is false with fewer than MinBaseline sizes.
func (b *Baselines) Deviates(key string, size int64) (deviates, known bool) {
	r := b.Routes[key]
	if r == nil || len(r.Sizes) < MinBaseline {
		return false, false
	}
	med := median(r.Sizes)
	dev := make([]int64, len(r.Sizes))
	for i, s := range r.Sizes {
		dev[i] = abs64(s - med)
	}
	mad := median(dev)
	limit := max(float64(SizeFloor), float64(med)/2, 3*1.4826*float64(mad))
	return float64(size-med) > limit, true
}

func median(xs []int64) int64 {
	s := append([]int64(nil), xs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	if n := len(s); n%2 == 1 {
		return s[n/2]
	} else {
		return (s[n/2-1] + s[n/2]) / 2
	}
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// Frame is a file and a line an error log names.
type Frame struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

// ErrorEvent is one error log entry: when, the frames it names, and
// whether its log is verified.
type ErrorEvent struct {
	Time     time.Time `json:"time"`
	Frames   []Frame   `json:"frames"`
	Verified bool      `json:"verified"`
	From     string    `json:"from,omitempty"`
}

// The times error logs write, and the frames they name. Times without a
// zone are the host's (loc).
var (
	phpTime    = regexp.MustCompile(`^\[(\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2})(?: ([A-Za-z_/+-]+))?\]`)
	nginxTime  = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[`)
	apacheTime = regexp.MustCompile(`^\[[A-Za-z]{3} ([A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2})(?:\.\d+)? (\d{4})\]`)
	isoTime    = regexp.MustCompile(`^\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(?:[.,]\d+)?(Z|[+-]\d{2}:?\d{2})?`)
	// The runtime's own location on an entry's line: PHP's "in FILE on
	// line N" ending a PHP message, in the whole line's shape of each log
	// that carries PHP's messages, the message's prefix at its fixed
	// place (phpLocation). The message echoes what the request sent, and
	// a server appends request fields after it, so where the message ends
	// is taken only where it is certain; any doubt, no frame.
	phpLevel  = `PHP (?:Fatal error|Warning|Notice|Parse error|Deprecated|Catchable fatal error|Recoverable fatal error|Strict Standards|Core error|Compile error|User (?:error|warning|notice|deprecated)):`
	phpOwn    = regexp.MustCompile(`^\[[^\]]+\] ` + phpLevel + ` .* in (/\S+?) on line (\d+)$`)
	apachePHP = regexp.MustCompile(`^\[[^\]]+\](?: \[[^\]]*\])+ ` + phpLevel + ` .* in (/\S+?) on line (\d+)$`)
	nginxPHP  = regexp.MustCompile(`^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d \[\w+\] \d+#\d+: \*\d+ FastCGI sent in stderr: "PHP message: ` + phpLevel + ` .* in (/\S+?) on line (\d+)"$`)
	nginxEnd  = regexp.MustCompile(`on line \d+" while reading `)
	apacheRef = regexp.MustCompile(`on line \d+, referer: `)
	lineEnd   = regexp.MustCompile(`on line \d+$`)
)

// phpLocation is the file and line PHP wrote ending its message on l, or
// nil when that is not certain:
//   - PHP's own log: the line's end.
//   - nginx: the message ends at `on line N" while reading `, which must
//     be there exactly once (the request's fields after it, the message
//     before it, could hold another).
//   - Apache: the line's end when no ", referer: " is on it; when one is
//     (and the client's text after it), `on line N, referer: ` must be
//     there exactly once and the line must not end with a location too.
func phpLocation(l string) []string {
	if m := phpOwn.FindStringSubmatch(l); m != nil {
		return m
	}
	if strings.Contains(l, "FastCGI sent in stderr: ") {
		ends := nginxEnd.FindAllStringIndex(l, -1)
		if len(ends) != 1 {
			return nil
		}
		return nginxPHP.FindStringSubmatch(l[:ends[0][1]-len(" while reading ")])
	}
	if !strings.HasPrefix(l, "[") {
		return nil
	}
	if lineEnd.MatchString(l) && !strings.Contains(l, ", referer: ") {
		return apachePHP.FindStringSubmatch(l)
	}
	refs := apacheRef.FindAllStringIndex(l, -1)
	if len(refs) != 1 || lineEnd.MatchString(l) { // a referer marker and a location at the end: either may be the client's
		return nil
	}
	return apachePHP.FindStringSubmatch(l[:refs[0][1]-len(", referer: ")])
}

// ErrorEvents reads an error log's lines: an entry is a line with a time,
// its frame the runtime's own location on that line, nothing else: PHP's
// location only where it certainly ends the message (phpLocation), an
// absolute path. The lines after an entry (a traceback's frames) are not
// taken: a message keeps the newlines the request sent, so they may be
// the request's text. An entry made of the request's text after such a
// newline remains possible; one kind of evidence alone is at most high
// (SeverityWith).
func ErrorEvents(lines []string, verified bool, from string, loc *time.Location) []ErrorEvent {
	var out []ErrorEvent
	add := func(m []string) {
		e := &out[len(out)-1]
		if n, err := strconv.Atoi(m[2]); err == nil && len(e.Frames) < 32 {
			e.Frames = append(e.Frames, Frame{File: m[1], Line: n})
		}
	}
	for _, l := range lines {
		l = hostenv.MaskSecrets(l)
		if t, ok := errorTime(l, loc); ok {
			out = append(out, ErrorEvent{Time: t, Verified: verified, From: from})
			if m := phpLocation(l); m != nil {
				add(m)
			}
			continue
		}
		// A line without a time is never a frame: a message keeps the
		// newlines the request sent, so a "frame line" after an entry may
		// be the request's own text (review 1 of #90, N-10).
	}
	return out
}

func errorTime(l string, loc *time.Location) (time.Time, bool) {
	if m := phpTime.FindStringSubmatch(l); m != nil {
		zone := loc
		if m[2] != "" {
			if z, err := time.LoadLocation(m[2]); err == nil {
				zone = z
			}
		}
		t, err := time.ParseInLocation("02-Jan-2006 15:04:05", m[1], zone)
		return t, err == nil
	}
	if m := nginxTime.FindStringSubmatch(l); m != nil {
		t, err := time.ParseInLocation("2006/01/02 15:04:05", m[1], loc)
		return t, err == nil
	}
	if m := apacheTime.FindStringSubmatch(l); m != nil {
		t, err := time.ParseInLocation("Jan 2 15:04:05 2006", m[1]+" "+m[2], loc)
		return t, err == nil
	}
	if m := isoTime.FindStringSubmatch(l); m != nil {
		s := strings.Replace(m[1], " ", "T", 1)
		if m[2] != "" {
			z := m[2]
			if z != "Z" && !strings.Contains(z, ":") {
				z = z[:3] + ":" + z[3:]
			}
			t, err := time.Parse(time.RFC3339, s+z)
			return t, err == nil
		}
		t, err := time.ParseInLocation("2006-01-02T15:04:05", s, loc)
		return t, err == nil
	}
	return time.Time{}, false
}

// sinkFile: an error log's file (absolute, as the runtime names it) is the
// audit's sink file (relative to the code root, or absolute): the logged
// one ends with the sink's at a path segment.
func sinkFile(logged, sink string, roots []string) bool {
	a := path.Clean("/" + strings.TrimPrefix(logged, "/"))
	if path.IsAbs(sink) {
		return a == path.Clean(sink)
	}
	if len(roots) > 0 {
		for _, r := range roots {
			if a == path.Clean(path.Join("/", r, sink)) {
				return true
			}
		}
		return false
	}
	b := path.Clean("/" + sink)
	if strings.Count(b, "/") < 2 {
		return false // one segment: it would match any directory's file of that name
	}
	return strings.HasSuffix(a, b) // never the other way: a short logged name would match many sinks
}

// Evidence is what L3 is judged on.
type Evidence struct {
	Baselines *Baselines
	Errors    []ErrorEvent
	// CodeRoots: where the audited code lives (the sink's file relative
	// to one of them): an error log's file must be one of those exactly.
	// None: it must end with the sink's file, and that must be at least
	// two segments (x.php alone would match any directory's).
	CodeRoots []string
}

// Upgrade raises an L2 attempt to L3 when the evidence says it likely
// worked, said in Success (Chinese); it reports whether it did. method is
// the request's, for the baseline's key.
func Upgrade(a *Attempt, method string, ev Evidence) bool {
	if a.Level != LevelPayload {
		return false
	}
	if !a.LogVerified { // the request itself must be one a trusted log wrote
		return false
	}
	var why []string
	// Size: a 2xx response larger than the route's usual by more than the
	// request itself could echo back (a 500 is an error page: not size
	// evidence).
	if a.Status >= 200 && a.Status < 300 && ev.Baselines != nil {
		if dev, known := ev.Baselines.Deviates(RouteKey(method, a.Route, a.Path), a.Bytes-int64(a.ReqLen)); known && dev {
			why = append(why, "回應碼 "+strconv.Itoa(a.Status)+"，回應大小 "+strconv.FormatInt(a.Bytes, 10)+" bytes 明顯大於這條路由平常的大小")
		}
	}
	if a.File != "" && a.Line > 0 && !a.Time.IsZero() {
	errors:
		for _, e := range ev.Errors {
			if d := e.Time.Sub(a.Time); !e.Verified || d > ErrorWindow || d < -ErrorBefore {
				continue
			}
			for _, f := range e.Frames {
				if f.Line == a.Line && sinkFile(f.File, a.File, ev.CodeRoots) {
					why = append(why, "請求後 120 秒內，錯誤記錄指向這個 sink 的檔案與行號（"+a.File+":"+strconv.Itoa(a.Line)+"）")
					break errors
				}
			}
		}
	}
	if len(why) == 0 {
		return false
	}
	a.Level, a.Success, a.Evidence = LevelSuccess, strings.Join(why, "；"), len(why)
	a.Severity = a.SeverityWith(false)
	return true
}
