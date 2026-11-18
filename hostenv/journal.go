package hostenv

// journald, read one unit at a time from where the last read stopped: the
// PHP-FPM, gunicorn, uwsgi, node... units whose stderr (PHP errors, Python
// tracebacks) shentu detect matches against this host's vulnerabilities.
// Only the fields journald fills in itself are believed.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Slots of the journal reads: a unit name (never an option: it cannot
// start with "-") and a journal cursor.
const (
	SlotUnit   = "\x00slot:unit"
	SlotCursor = "\x00slot:cursor"
)

func init() {
	slotShapes[SlotUnit] = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.@\\-]{0,200}\.service$`)
	slotShapes[SlotCursor] = regexp.MustCompile(`^s=[0-9a-f]{32};i=[0-9a-f]+;b=[0-9a-f]{32};m=[0-9a-f]+;t=[0-9a-f]+;x=[0-9a-f]+$`)
	for _, a := range journalUnitArgvs() {
		registerBig(a, 0, JournalTimeout)
	}
}

// journalFields are the fields asked for: the message, and those journald
// fills in from the sender's credentials (the _ ones), which the sender
// cannot set. __CURSOR and __REALTIME_TIMESTAMP come always.
const journalFields = "--output-fields=MESSAGE,_SYSTEMD_UNIT,_UID,_PID,_COMM,_TRANSPORT"

// journalUnitArgv is a unit's read: after a cursor or since a time, with
// --output-fields (systemd 236+) or without. Without it is still -o json,
// and still verified: the fields that are believed (_SYSTEMD_UNIT, _UID,
// _PID, _COMM, _TRANSPORT) are filled in by journald from the sender's
// credentials whether they are asked for or not, and a sender cannot set a
// field starting with "_". --output-fields only leaves out the others; it
// is no part of the trust. (Plan 0743f0 first said short-iso, unverified.)
func journalUnitArgv(bin string, after, fields bool) []string {
	a := []string{bin, "-u", SlotUnit}
	if after {
		a = append(a, "--after-cursor", SlotCursor)
	} else {
		a = append(a, "--since", SlotTime)
	}
	a = append(a, "-o", "json", "--all") // --all: a field past 4096 bytes comes as itself, not null
	if fields {
		a = append(a, journalFields)
	}
	return append(a, "--no-pager")
}

func journalUnitArgvs() [][]string {
	var out [][]string
	for _, bin := range []string{"/usr/bin/journalctl", "/bin/journalctl"} {
		for _, after := range []bool{true, false} {
			for _, fields := range []bool{true, false} {
				out = append(out, journalUnitArgv(bin, after, fields))
			}
		}
	}
	return out
}

// JournalEntry is one journal entry, as journald recorded it.
type JournalEntry struct {
	Cursor    string    `json:"cursor"`
	Time      time.Time `json:"time"`
	Unit      string    `json:"unit,omitempty"` // _SYSTEMD_UNIT: the cgroup the sender ran in
	UID       int       `json:"uid"`            // _UID; -1 when absent
	PID       int       `json:"pid,omitempty"`
	Comm      string    `json:"comm,omitempty"`
	Transport string    `json:"transport,omitempty"` // stdout, journal, syslog, kernel, driver, audit
	Message   string    `json:"message"`             // what the sender wrote: never trusted; cut at MaxJournalMessage
	// MessageMissing: journald gave no MESSAGE as text or bytes (null, or
	// none): the entry is counted, not taken as an empty message.
	MessageMissing bool `json:"message_missing,omitempty"`
	Cut            bool `json:"cut,omitempty"` // Message was longer than MaxJournalMessage
}

// MaxJournalMessage is the longest message kept from one entry.
const MaxJournalMessage = 64 << 10

// MaxJournalLine is the longest line of journalctl's JSON read whole; a
// longer entry (--all gives fields past 4096 bytes whole) is cut, its
// cursor taken from its start (journalctl writes __CURSOR first), and the
// read goes on: one huge entry never stalls the cursor.
const MaxJournalLine = 256 << 10

// ErrCursorRejected: journalctl refused the cursor itself (could not parse
// or seek to it). Other failures keep the cursor.
var ErrCursorRejected = errors.New("hostenv: journal cursor rejected")

var cutCursor = regexp.MustCompile(`^\{"__CURSOR"\s*:\s*"([^"\\]+)"`)

// ErrStopJournal, returned by a ReadJournal consumer, ends the read there:
// the cursor returned is the last entry consumed.
var ErrStopJournal = errors.New("hostenv: journal read stopped")

// ReadJournal reads unit's entries after the cursor after (empty: since
// since), giving each to fn, and returns the cursor of the last one given
// ("" if none: keep the old one). A systemd too old for --output-fields is
// read without it. A journal hiding the system's entries from this user is
// a permission error, not an empty journal.
func ReadJournal(ctx context.Context, src Source, unit, after string, since time.Time, fn func(JournalEntry) error) (last string, err error) {
	ctx, cancel := context.WithTimeout(ctx, JournalTimeout)
	defer cancel()
	var stop, bad error
	n := 0
	line := func(l string, cut bool) {
		if stop != nil || strings.TrimSpace(l) == "" {
			return
		}
		var e JournalEntry
		if cut { // the JSON is not whole: its cursor, and that it was cut
			m := cutCursor.FindStringSubmatch(l)
			if m == nil {
				bad = errors.New("an entry past MaxJournalLine without its cursor at the start")
				return
			}
			e = JournalEntry{Cursor: m[1], UID: -1, MessageMissing: true, Cut: true}
		} else {
			var perr error
			if e, perr = parseJournalJSON(l); perr != nil {
				bad = perr
				return
			}
		}
		if err := fn(e); err != nil {
			stop = err
			cancel()
			return
		}
		last, n = e.Cursor, n+1
	}
	run := func(bin string, fields bool) (CmdResult, error) {
		argv := journalUnitArgv(bin, after != "", fields)
		argv[2] = unit
		if after != "" {
			argv[4] = after
		} else {
			argv[4] = since.UTC().Format("2006-01-02 15:04:05") + " UTC" // journalctl reads a bare time as local
		}
		res, err := RunLinesCut(ctx, src, argv, MaxJournalLine, line)
		if err == nil && res.ExitCode != 0 {
			err = &exitError{res.ExitCode}
			if after != "" && n == 0 && strings.Contains(strings.ToLower(res.Stderr), "cursor") {
				err = fmt.Errorf("%w: %s", ErrCursorRejected, strings.TrimSpace(res.Stderr))
			}
		}
		return res, err
	}
	var res CmdResult
	for _, bin := range []string{"/usr/bin/journalctl", "/bin/journalctl"} {
		res, err = run(bin, true)
		if err != nil && n == 0 && stop == nil && strings.Contains(res.Stderr, "output-fields") { // systemd < 236
			res, err = run(bin, false)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			break // a missing binary is the only reason to try the other path
		}
	}
	switch {
	case stop != nil:
		if errors.Is(stop, ErrStopJournal) {
			return last, nil
		}
		return last, stop
	case err == nil && n == 0 && strings.Contains(res.Stderr, "not seeing messages from other users and the system"):
		return "", fmt.Errorf("%w: journald hides the system's entries from this user", fs.ErrPermission)
	case err == nil && bad != nil:
		return last, fmt.Errorf("journal entry not understood: %w", bad)
	}
	return last, err
}

// parseJournalJSON reads one entry of journalctl -o json. A field journald
// could not give as text (binary, or too large) comes as an array of
// bytes, or null.
func parseJournalJSON(l string) (JournalEntry, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(l), &m); err != nil {
		return JournalEntry{}, err
	}
	str := func(k string) string {
		raw, ok := m[k]
		if !ok {
			return ""
		}
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s
		}
		var bs []byte
		var ns []int
		if json.Unmarshal(raw, &ns) == nil {
			for _, n := range ns {
				bs = append(bs, byte(n))
			}
			return string(bs)
		}
		return ""
	}
	e := JournalEntry{Cursor: str("__CURSOR"), Unit: str("_SYSTEMD_UNIT"), Comm: str("_COMM"), Transport: str("_TRANSPORT"), Message: str("MESSAGE"), UID: -1}
	if raw, ok := m["MESSAGE"]; !ok || string(raw) == "null" {
		e.MessageMissing = true
	}
	if len(e.Message) > MaxJournalMessage {
		e.Message, e.Cut = e.Message[:MaxJournalMessage], true
	}
	if e.Cursor == "" {
		return e, errors.New("no __CURSOR")
	}
	if us, err := strconv.ParseInt(str("__REALTIME_TIMESTAMP"), 10, 64); err == nil {
		e.Time = time.UnixMicro(us).UTC()
	}
	if u, err := strconv.Atoi(str("_UID")); err == nil {
		e.UID = u
	}
	e.PID, _ = strconv.Atoi(str("_PID"))
	return e, nil
}

// appExe are the programs whose units' output detect reads: PHP-FPM and the
// application servers of Python, Node and Ruby.
var appExe = regexp.MustCompile(`^(?:php[0-9.]*-fpm[0-9.]*|php-fpm|gunicorn|uwsgi|uvicorn|hypercorn|daphne|node|nodejs|pm2|pm2-runtime|puma|unicorn|passenger)$`)

const maxUnits = 256

// AppUnit is a systemd unit running PHP-FPM or an application server.
type AppUnit struct {
	Name string `json:"name"`
	// User is the unit's User= ("" when it has none: the application runs
	// as root unless it drops privileges itself).
	User string `json:"user,omitempty"`
	// FPM: PHP-FPM, whose root master writes its own messages and whose
	// workers run PHP as the pools' users, never root (php-fpm refuses
	// without -R).
	FPM bool `json:"fpm,omitempty"`
	// Elevated: an ExecStart runs with full privileges whatever User= says
	// ('+' or '!'), PHP-FPM may run pools as root (-R, a pool's user root),
	// or the effective User= could not be told (a drop-in unread).
	Elevated bool `json:"elevated,omitempty"`
}

// RunsAppAsRoot: the application's own code may run as root in this unit,
// so a root message from it may be the application's.
func (u AppUnit) RunsAppAsRoot() bool {
	if u.Elevated {
		return true
	}
	if u.FPM {
		return false
	}
	return u.User == "" || u.User == "root" || u.User == "0"
}

// AppUnits is the enabled systemd units running PHP-FPM or an application
// server (ExecStart's program, or python -m <it>), sorted. Partial when some
// unit file could not be read.
func (LinuxCollector) AppUnits(src Source) Obs[[]AppUnit] {
	conf := WebConf{Root: "/", Owner: 0} // unit files live under /etc, /lib and /usr/lib: root's, not writable by others
	seen := map[string]bool{}
	var out []AppUnit
	var unread []string
	for _, wants := range Glob(src, "/etc/systemd/system/*.wants") {
		names, _ := src.ReadDir(wants)
		for _, n := range names {
			if !strings.HasSuffix(n, ".service") || seen[n] || len(seen) >= maxUnits {
				continue
			}
			seen[n] = true
			b, why := readWebConf(src, path.Join(wants, n), conf)
			if why != "" {
				unread = append(unread, n+" ("+why+")")
				continue
			}
			u, ok := appUnit(src, n, b, conf)
			if ok {
				out = append(out, u)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(unread) > 0 {
		return Partial(out, ReasonPermission, "unit files unread, their units may be missing: "+strings.Join(unread, "; "))
	}
	return OK(out)
}

// unitPaths are systemd's unit search paths, the highest priority first
// (systemd.unit(5)): a unit file or a drop-in of the same name in an
// earlier one wins.
var unitPaths = []string{
	"/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient", "/run/systemd/generator.early",
	"/etc/systemd/system", "/etc/systemd/system.attached", "/run/systemd/system", "/run/systemd/system.attached",
	"/run/systemd/generator", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system",
	"/run/systemd/generator.late",
}

// dropInNames are the names whose <name>.d directories apply to unit:
// the type's (service.d), each dash prefix's (php8.2-.service.d for
// php8.2-fpm.service), a template's (app@.service.d), and its own.
func dropInNames(unit string) []string {
	base := strings.TrimSuffix(unit, ".service")
	names := []string{"service"}
	for i := 0; i < len(base); i++ {
		if base[i] == '-' {
			names = append(names, base[:i+1]+".service")
		}
	}
	if at := strings.IndexByte(base, '@'); at >= 0 && at < len(base)-1 {
		names = append(names, base[:at+1]+".service")
	}
	return append(names, unit)
}

// appUnit reads what matters of a unit: whether it runs an application,
// its effective User=, and whether anything may run it as root. The unit
// file is the one of the highest-priority path (an /etc override beats
// /lib's), then its drop-ins apply as systemd applies them: from every
// path and every applicable name, a file name in a higher-priority path
// hiding the same name in a lower one, in file name order. Anything that
// cannot be read or told fails closed: Elevated.
// unitConfs are the unit's file, the one of the highest-priority path, and
// its drop-ins in the order systemd applies them (appUnit); unread: one of
// them could not be read or listed.
func unitConfs(src Source, name string, unit []byte, conf WebConf) (all [][]byte, unread bool) {
	tmpl := name
	if at := strings.IndexByte(name, '@'); at >= 0 {
		tmpl = name[:at+1] + ".service"
	}
	for _, dir := range unitPaths { // a full override of the unit file
		found := false
		for _, n := range []string{name, tmpl} {
			f := path.Join(dir, n)
			if _, err := Stat(src, f); err != nil {
				continue
			}
			b, why := readWebConf(src, f, conf)
			if why != "" {
				unread = true
			} else {
				unit = b
			}
			found = true
			break
		}
		if found {
			break
		}
	}
	type dropIn struct {
		file string
		prio int
	}
	chosen := map[string]dropIn{} // file name -> the highest-priority one
	for prio, dir := range unitPaths {
		for _, n := range dropInNames(name) {
			d := path.Join(dir, n+".d")
			entries, err := src.ReadDir(d)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, ErrNotRecorded) {
					unread = true // there, but not listed: a User= we cannot see
				}
				continue
			}
			for _, e := range entries {
				if !strings.HasSuffix(e, ".conf") {
					continue
				}
				if c, ok := chosen[e]; !ok || prio < c.prio {
					chosen[e] = dropIn{path.Join(d, e), prio}
				}
			}
		}
	}
	files := make([]string, 0, len(chosen))
	for f := range chosen {
		files = append(files, f)
	}
	sort.Strings(files)
	all = [][]byte{unit}
	for _, f := range files {
		b, why := readWebConf(src, chosen[f].file, conf)
		if why != "" {
			unread = true
			continue
		}
		all = append(all, b)
	}
	return all, unread
}

func appUnit(src Source, name string, unit []byte, conf WebConf) (AppUnit, bool) {
	u := AppUnit{Name: name}
	all, unread := unitConfs(src, name, unit, conf)
	u.Elevated = unread
	found := false
	for _, b := range all {
		ok, fpm, priv := unitRunsApp(b)
		found = found || ok
		u.FPM = u.FPM || fpm
		u.Elevated = u.Elevated || priv
		if usr, set := unitUser(b); set {
			u.User = usr // the last assignment wins; an empty one resets to root
		}
		if dynamicUser(b) {
			u.Elevated = true
		}
	}
	if strings.Contains(u.User, "%") { // a specifier (%i): the instance names the user
		u.Elevated = true
	}
	if u.FPM && fpmPoolAsRoot(src) {
		u.Elevated = true
	}
	return u, found
}

// fpmPoolAsRoot: a PHP-FPM pool runs as root, or forwards its workers'
// output to the master's log (catch_workers_output: the master, root, then
// logs what PHP wrote), or a pool's configuration could not be read (so
// either may be).
func fpmPoolAsRoot(src Source) bool {
	l := &logLoader{src: src, conf: DefaultWebConf, out: map[string]*LogSource{}}
	l.phpFPM()
	if len(l.unread) > 0 || l.catchWorkers {
		return true
	}
	for _, u := range l.users {
		if u == "root" || u == "0" || u == "#0" {
			return true
		}
	}
	return false
}

// unitUser is the unit file's last User=, and whether it has one: an
// empty User= resets it (root).
func unitUser(b []byte) (string, bool) {
	u, set := "", false
	for _, ln := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(ln), "="); ok && strings.TrimSpace(k) == "User" {
			u, set = strings.TrimSpace(v), true
		}
	}
	return u, set
}

// dynamicUser: the unit sets DynamicUser= at all (its account is made at
// start; not one to compare): taken as not known.
func dynamicUser(b []byte) bool {
	for _, ln := range strings.Split(string(b), "\n") {
		if k, _, ok := strings.Cut(strings.TrimSpace(ln), "="); ok && strings.TrimSpace(k) == "DynamicUser" {
			return true
		}
	}
	return false
}

var fpmExe = regexp.MustCompile(`^(?:php[0-9.]*-fpm[0-9.]*|php-fpm)$`)

// unitRunsApp: an ExecStart of the unit file starts one of appExe; fpm, it
// is PHP-FPM (not told it may run as root); priv, an ExecStart of the file
// runs with full privileges ('+', '!') or is PHP-FPM allowed root (-R).
func unitRunsApp(b []byte) (ok, fpm, priv bool) {
	for _, ln := range strings.Split(string(b), "\n") {
		k, v, kv := strings.Cut(strings.TrimSpace(ln), "=")
		if !kv || strings.TrimSpace(k) != "ExecStart" {
			continue
		}
		v = strings.TrimSpace(v)
		prefix := v[:len(v)-len(strings.TrimLeft(v, "@-:+!|"))]
		if strings.ContainsAny(prefix, "+!") {
			priv = true
		}
		f := strings.Fields(v[len(prefix):])
		if len(f) == 0 {
			continue
		}
		exe := path.Base(f[0])
		if appExe.MatchString(exe) {
			ok = true
			if fpmExe.MatchString(exe) {
				fpm = true
				for _, a := range f[1:] {
					if a == "-R" || a == "--allow-to-run-as-root" {
						priv = true
					}
				}
			}
			continue
		}
		if strings.HasPrefix(exe, "python") || exe == "env" {
			for i, a := range f[1:] {
				if appExe.MatchString(path.Base(a)) || (a == "-m" && i+2 < len(f) && appExe.MatchString(f[i+2])) {
					ok = true
				}
			}
		}
	}
	return ok, fpm, priv
}
