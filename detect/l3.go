package detect

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
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
	ErrorWindow   = 120 * time.Second
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
}

// RouteKey is the baseline's key for an attempt or a request: the method
// and the code sink's route pattern; the routed path when there is no
// route (a package's vulnerability).
func RouteKey(method string, route *engine.RouteRef, routedPath string) string {
	if route != nil && route.Pattern != "" {
		return strings.ToUpper(method) + " " + route.Pattern
	}
	return strings.ToUpper(method) + " path:" + routedPath
}

// LoadBaselines reads dir's baselines.json; none is empty; one that does
// not parse is set aside and said (Note).
func LoadBaselines(dir string, now time.Time) (*Baselines, error) {
	b := &Baselines{Version: 1, Routes: map[string]*baseline{}}
	p := filepath.Join(dir, BaselinesFile)
	raw, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return b, nil
	}
	if err != nil {
		return nil, err
	}
	var got Baselines
	if err := json.Unmarshal(raw, &got); err != nil || got.Version != 1 {
		bad := p + ".bad-" + strconv.FormatInt(now.Unix(), 10)
		if rerr := os.Rename(p, bad); rerr != nil {
			return nil, errors.Join(err, rerr)
		}
		b.Note = "baselines.json did not parse and was set aside as " + filepath.Base(bad) + "; sizes are learnt again"
		return b, nil
	}
	if got.Routes != nil {
		b.Routes = got.Routes
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
	sort.Slice(keys, func(i, j int) bool {
		x, y := b.Routes[keys[i]].Last, b.Routes[keys[j]].Last
		if !x.Equal(y) {
			return x.After(y)
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys[n:] {
		delete(b.Routes, k)
	}
}

// Observe adds an ordinary response's size to key's baseline. The caller
// observes only requests with no hit, a 2xx status, from a verified log.
func (b *Baselines) Observe(key string, size int64, at time.Time) {
	r := b.Routes[key]
	if r == nil {
		if len(b.Routes) >= MaxBaselines+MaxBaselines/4 {
			b.evict(MaxBaselines - 1)
		}
		r = &baseline{}
		b.Routes[key] = r
	}
	r.Sizes = append(r.Sizes, size)
	if len(r.Sizes) > BaselineKeep {
		r.Sizes = r.Sizes[len(r.Sizes)-BaselineKeep:]
	}
	if at.After(r.Last) {
		r.Last = at
	}
}

// Deviates says whether size stands out from key's baseline: farther from
// the median than three scaled MADs, half the median and SizeFloor. known
// is false with fewer than MinBaseline sizes.
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
	return float64(abs64(size-med)) > limit, true
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
	// line N" ending a PHP message (the line's end, or the quote nginx
	// closes FastCGI's stderr with), on a line holding one (phpMessage).
	// What comes before may echo request data, and a server's own error
	// (nginx's open() "..." failed) quotes the request's path: neither
	// ends a PHP message.
	phpWhere   = regexp.MustCompile(` in (/\S+?) on line (\d+)(?:"? while |"$|$)`)
	phpMessage = regexp.MustCompile(`\bPHP (?:Fatal error|Warning|Notice|Parse error|Deprecated|Error|Catchable fatal error|Recoverable fatal error|Strict Standards|Core error|Compile error|User (?:error|warning|notice|deprecated)):`)
	// Frame lines after an entry, each in the runtime's own shape: PHP's
	// "#0 /srv/x.php(12)", Python's '  File "/srv/x.py", line 40', Node's
	// "    at fn (/srv/x.js:7:13)". Any other line without a time is not
	// the entry's.
	frameLines = []*regexp.Regexp{
		regexp.MustCompile(`^#\d+ (/[^\s()"']+)\((\d+)\)`),
		regexp.MustCompile(`^\s+File "(/[^"]+)", line (\d+)`),
		regexp.MustCompile(`^\s+at (?:\S+ \()?(/[^\s()"':]+):(\d+)(?::\d+)?\)?$`),
	}
	// What servers append to an error line from the request itself
	// (nginx's ", client: ... request: ...", Apache's ", referer: ..."):
	// cut before frames are looked for, as the client writes it.
	requestFields = regexp.MustCompile(`, (?:client|server|request|upstream|host|referrer|referer): `)
)

// ErrorEvents reads an error log's lines: an entry is a line with a time,
// its frame the runtime's own location on it, and the frame lines after
// it (a traceback's). Only what the runtime writes is taken: the request
// fields a server appends are cut, a frame is an absolute path, and a
// line without a time joins the entry only in a frame line's shape. An
// attacker's request echoed in the log cannot name a sink's line.
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
			if i := requestFields.FindStringIndex(l); i != nil {
				l = l[:i[0]]
			}
			if phpMessage.MatchString(l) {
				if ms := phpWhere.FindAllStringSubmatch(l, -1); len(ms) > 0 {
					add(ms[len(ms)-1])
				}
			}
			continue
		}
		if len(out) == 0 {
			continue // frames before any time: no time to compare
		}
		for _, re := range frameLines {
			if m := re.FindStringSubmatch(l); m != nil {
				add(m)
				break
			}
		}
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
func sinkFile(logged, sink string) bool {
	a, b := path.Clean("/"+strings.TrimPrefix(logged, "/")), path.Clean("/"+strings.TrimPrefix(sink, "/"))
	return a == b || strings.HasSuffix(a, b) // never the other way: a short logged name would match many sinks
}

// Evidence is what L3 is judged on.
type Evidence struct {
	Baselines *Baselines
	Errors    []ErrorEvent
}

// Upgrade raises an L2 attempt to L3 when the evidence says it likely
// worked, said in Success (Chinese); it reports whether it did. method is
// the request's, for the baseline's key.
func Upgrade(a *Attempt, method string, ev Evidence) bool {
	if a.Level != LevelPayload {
		return false
	}
	var why string
	okStatus := a.Status >= 200 && a.Status < 300 || a.Status == 500
	if okStatus && a.LogVerified && ev.Baselines != nil {
		if dev, known := ev.Baselines.Deviates(RouteKey(method, a.Route, a.Path), a.Bytes); known && dev {
			why = "回應碼 " + strconv.Itoa(a.Status) + "，回應大小 " + strconv.FormatInt(a.Bytes, 10) + " bytes 明顯偏離這條路由平常的大小"
		}
	}
	if why == "" && a.File != "" && a.Line > 0 && !a.Time.IsZero() {
		for _, e := range ev.Errors {
			if !e.Verified || e.Time.Sub(a.Time) > ErrorWindow || a.Time.Sub(e.Time) > ErrorWindow {
				continue
			}
			for _, f := range e.Frames {
				if f.Line == a.Line && sinkFile(f.File, a.File) {
					why = "請求前後 120 秒內，錯誤記錄指向這個 sink 的檔案與行號（" + a.File + ":" + strconv.Itoa(a.Line) + "）"
				}
			}
			if why != "" {
				break
			}
		}
	}
	if why == "" {
		return false
	}
	a.Level, a.Success = LevelSuccess, why
	a.Severity = SeverityOf(LevelSuccess, a.Severe, false, a.Verified)
	return true
}
