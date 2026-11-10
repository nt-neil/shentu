package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nt-neil/shentu/rules/engine"
)

// The injection results of one audit are kept for the next one (mode 0600,
// next to the code index): per file, its content hash, what the rules found in
// it on its own, what following its calls across files found, and the files
// its calls were followed into. They hold rule ids, paths and line numbers,
// never code. A later audit of the same roots takes a file's results while
// the file is unchanged (and, for calls across files, the files they reached
// and the names the project declares in its language), so its time goes to
// files changed since and to those the last audits had no time for: on a
// project too large for one audit's time, the calls across files are covered
// a part at a time and the summary tells how far that has got.

// callStateVersion changes whenever callState or what it means changes.
const callStateVersion = "1"

type callState struct {
	Version string                `json:"v"`
	Build   string                `json:"b"`           // the binary, rules and limits the results came from
	Digest  map[string]string     `json:"d,omitempty"` // language → engine.Project.IndexDigest
	Files   map[string]*fileState `json:"f"`
}

type fileState struct {
	Hash  string      `json:"h"`
	Own   *passResult `json:"o,omitempty"` // the file on its own (Engine.Scan)
	Calls *passResult `json:"c,omitempty"` // its calls across files (Project.ScanCallsPart)
	Part  *partResult `json:"p,omitempty"` // ... when the clock cut them short: the rules done so far
	Slow  []string    `json:"s,omitempty"` // rules left out for this content: too slow for one audit
	Deps  []string    `json:"d,omitempty"` // files its functions' calls were followed into
}

// partResult is how far following a file's calls got in audits the clock
// cut short: the rules followed to their end and what they found.
type partResult struct {
	Rules []string         `json:"r"`
	Found []engine.Finding `json:"f,omitempty"`
	Cut   bool             `json:"c,omitempty"` // a cap cut one of them short
	Tries map[string]int   `json:"t,omitempty"` // rule → audits in a row the clock cut it short
}

type passResult struct {
	Found  []engine.Finding `json:"f,omitempty"`
	Reason string           `json:"r,omitempty"` // unfinishedReason; "" when it ran to the end
	Gen    bool             `json:"g,omitempty"` // the file is minified or bundled JavaScript
}

// callStateFile is where the results for these roots are kept ("" for none):
// one file per set of roots, as a narrower audit indexes other files.
func callStateFile(roots []string) string {
	idx := codeIndexFile()
	if idx == "" {
		return ""
	}
	rs := make([]string, len(roots))
	for i, r := range roots {
		rs[i] = filepath.Clean(r)
	}
	sort.Strings(rs)
	sum := sha256.Sum256([]byte(strings.Join(rs, "\x00")))
	return filepath.Join(filepath.Dir(idx), "codecalls-"+hex.EncodeToString(sum[:8])+".json")
}

// auditBuild names what the results depend on besides the code: this binary
// (its size and time), the rules and the engine's limits.
func auditBuild(eng *engine.Engine) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s %+v\n", callStateVersion, eng.Limits)
	if exe, err := os.Executable(); err == nil {
		if info, err := os.Stat(exe); err == nil {
			fmt.Fprintf(h, "%d %d\n", info.Size(), info.ModTime().UnixNano())
		}
	}
	h.Write([]byte(rulesDigest))
	return hex.EncodeToString(h.Sum(nil))
}

func loadCallState(name, build string) *callState {
	st := &callState{Version: callStateVersion, Build: build, Digest: map[string]string{}, Files: map[string]*fileState{}}
	if name == "" {
		return st
	}
	b, err := os.ReadFile(name)
	if err != nil {
		return st
	}
	var old callState
	if json.Unmarshal(b, &old) != nil || old.Version != callStateVersion || old.Build != build || old.Files == nil {
		return st
	}
	if old.Digest == nil {
		old.Digest = map[string]string{}
	}
	return &old
}

// saveCallState writes the state with mode 0600, replacing the old one in one step.
func saveCallState(name string, st *callState) {
	if name == "" {
		return
	}
	b, err := json.Marshal(st)
	if err != nil {
		return
	}
	if os.MkdirAll(filepath.Dir(name), 0o700) != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(name), ".codecalls-")
	if err != nil {
		return
	}
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmp.Name())
		}
	}()
	if tmp.Chmod(0o600) != nil {
		tmp.Close()
		return
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return
	}
	if tmp.Close() != nil {
		return
	}
	ok = os.Rename(tmp.Name(), name) == nil
}

// own returns the kept result of the file on its own, if its content is the same.
func (st *callState) own(p, hash string) *passResult {
	if fs := st.Files[p]; fs != nil && fs.Hash == hash {
		return fs.Own
	}
	return nil
}

// entry returns the file's state for this content, starting a new one when the
// content changed.
func (st *callState) entry(p, hash string) *fileState {
	fs := st.Files[p]
	if fs == nil || fs.Hash != hash {
		fs = &fileState{Hash: hash}
		st.Files[p] = fs
	}
	return fs
}

// useDigests drops the results across files of the languages whose declared
// names changed: a call may now resolve to another function.
func (st *callState) useDigests(pr *engine.Project, langs []string) {
	for _, lang := range langs {
		d := pr.IndexDigest(lang)
		if st.Digest[lang] == d {
			continue
		}
		st.Digest[lang] = d
		for p, fs := range st.Files {
			if engine.LangOf(p) == lang {
				fs.Calls, fs.Part, fs.Deps = nil, nil, nil
			}
		}
	}
}

// dropStale drops and lists the kept results across files that no longer
// hold: the file changed, or one its calls reached (or theirs, in turn)
// changed or is gone.
func (st *callState) dropStale(hash map[string]string) map[string]bool {
	bad := map[string]bool{}
	callers := map[string][]string{}
	var queue []string
	mark := func(f string) {
		if !bad[f] {
			bad[f] = true
			queue = append(queue, f)
		}
	}
	for f, fs := range st.Files {
		if fs.Hash != hash[f] {
			mark(f)
		}
		for _, d := range fs.Deps {
			callers[d] = append(callers[d], f)
			if g := st.Files[d]; g == nil || g.Hash != hash[d] {
				mark(d)
			}
		}
	}
	for len(queue) > 0 {
		f := queue[0]
		queue = queue[1:]
		for _, c := range callers[f] {
			mark(c)
		}
	}
	// Their results go now, not when they are scanned again: an audit that has
	// no time for one must not keep it for the next, where the change it
	// depended on would no longer show. What the file's own calls reach (Deps)
	// still holds while the file is unchanged.
	for f := range bad {
		if fs := st.Files[f]; fs != nil {
			fs.Calls, fs.Part = nil, nil
		}
	}
	return bad
}

// addDeps records the files a file's calls were followed into in this audit,
// with those kept from earlier audits of the same content.
func (fs *fileState) addDeps(deps []string) {
	if len(deps) == 0 {
		return
	}
	set := map[string]bool{}
	for _, d := range append(fs.Deps, deps...) {
		set[d] = true
	}
	fs.Deps = fs.Deps[:0]
	for d := range set {
		fs.Deps = append(fs.Deps, d)
	}
	sort.Strings(fs.Deps)
}

// keepOnly drops the files no longer in the audit.
func (st *callState) keepOnly(hash map[string]string) {
	for p := range st.Files {
		if _, ok := hash[p]; !ok {
			delete(st.Files, p)
		}
	}
}
