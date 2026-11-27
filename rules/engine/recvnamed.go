package engine

import (
	"maps"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// recvNamed returns the receivers names of the engine's PHP rules (lower
// case) that a PHP file names: as a name in the code (use MongoDB\Client,
// new CI_Model, class_alias, extends, a type, a call of db_select), one part
// of a qualified name each, or as a word in a string ('MongoDB\Client').
func recvNamed(e *Engine, toks []Token) []string {
	want := map[string]bool{}
	for _, r := range e.byLang["php"] {
		for _, n := range r.recvNames {
			want[n] = true
		}
	}
	if len(want) == 0 {
		return nil
	}
	got := map[string]bool{}
	for i, tk := range toks {
		switch tk.Kind {
		case Ident:
			if i > 0 && memberOp(true, toks[i-1]) {
				continue // $x->mongo, X::find: a member of something else, not the library's name
			}
			if n := strings.ToLower(tk.Text); want[n] {
				got[n] = true
			}
		case Str:
			low := strings.ToLower(tk.Text)
			for n := range want {
				if !got[n] && wordIn(low, n) {
					got[n] = true
				}
			}
		}
	}
	return slices.Sorted(maps.Keys(got))
}

// wordIn reports whether w occurs in s with no letter, digit or _ on either
// side: MongoDB in 'MongoDB\Client', not in 'Mongolia'.
func wordIn(s, w string) bool {
	word := func(c byte) bool {
		return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
	}
	for i := 0; ; {
		j := strings.Index(s[i:], w)
		if j < 0 {
			return false
		}
		j += i
		if (j == 0 || !word(s[j-1])) && (j+len(w) == len(s) || !word(s[j+len(w)])) {
			return true
		}
		i = j + 1
	}
}

// vendorPkg records the Composer package a vendor/ path is in
// (vendor/mongodb/mongodb/src/Client.php: mongodb/mongodb).
func (p *Project) vendorPkg(f string) {
	parts := strings.Split(path.Clean(filepath.ToSlash(f)), "/")
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] == "vendor" {
			p.pkgs[strings.ToLower(parts[i+1]+"/"+parts[i+2])] = true
		}
	}
}

// ownMethodOnly reports whether a method sink of rule r named method can be
// the project's own method only: the project never names the library the
// rule's receivers name (in its PHP, composer.json, composer.lock or a
// vendor/ path), some class of the project declares a method of that name,
// and every file was indexed to its end and read when needed. Any doubt
// counts the call as the rule's sink.
//
// p.named, p.pkgs and p.gap are fixed when NewProject has indexed every file,
// before any scan. p.unread and p.stopped can still grow during a scan, so a
// call decided before that is not decided again; the file read late was
// indexed already, so its mentions of the library are in p.named, and what
// it adds is a file gone or changed since indexing, or one whose parse was
// cut short by the clock or the work cap; the scan reports either as
// Unsteady.
func (p *Project) ownMethodOnly(r *crule, method string) bool {
	if p == nil || len(r.recvNames) == 0 && len(r.recvPkgs) == 0 || p.gap || p.stopped != "" || len(p.unread) > 0 {
		return false
	}
	for _, n := range r.recvNames {
		if p.named[n] {
			return false
		}
	}
	for _, k := range r.recvPkgs {
		if p.pkgs[k] {
			return false
		}
	}
	for k := range p.pkgs {
		for _, n := range r.recvNames {
			if wordIn(k, n) {
				return false // ext-mongodb, jenssegers/mongodb
			}
		}
	}
	p.methodsOnce.Do(func() {
		p.methods = map[string]bool{}
		for _, fi := range p.files {
			if baseLang(fi.Lang) != "php" {
				continue
			}
			for _, c := range fi.Classes {
				for _, m := range c.Methods {
					p.methods[strings.ToLower(m)] = true
				}
			}
		}
	})
	return p.methods[strings.ToLower(method)]
}
