package engine

import (
	"strconv"
	"strings"
)

// yields_to: where two rules report one sink, the rule that yields leaves it
// to the other (php-sqli-orderby-identifier's DB::raw inside laravel-raw's
// DB::select). A finding is left out only where the other rule reports the
// same line through the same sink call: each call this rule reported the line
// through is held by one of the other rule's, or holds one (DB::raw(...)
// inside DB::select(...), or the same ->where(...)). A line this rule also
// reports through another call, or through a sink the analysis did not see
// written out ("": a function's summary, a text sink), stays.

// spanText is the sink call t[i:end] as a text one call's can be found in:
// each token's kind and text, between separators.
func spanText(t []Token, i, end, _ int) string {
	if end > len(t) {
		end = len(t)
	}
	var b strings.Builder
	b.WriteByte('\x01')
	for _, tk := range t[i:end] {
		b.WriteString(strconv.Itoa(int(tk.Kind)))
		b.WriteByte('\x02')
		b.WriteString(tk.Text)
		b.WriteByte('\x01')
	}
	return b.String()
}

// yieldFindings leaves out of out the findings of a rule with yields_to that
// another rule takes (see above). spans holds, by rule id, the sink calls each
// line was reported through.
func yieldFindings(out []Finding, rules map[string]*crule, spans map[string]map[loc][]string) []Finding {
	reported := map[string]bool{} // rule id, path, line
	key := func(id, path string, line int) string { return id + "\x00" + path + "\x00" + strconv.Itoa(line) }
	for _, f := range out {
		reported[key(f.RuleID, f.Path, f.Line)] = true
	}
	kept := out[:0]
	for _, f := range out {
		if r := rules[f.RuleID]; r == nil || len(r.rule.YieldsTo) == 0 || !yields(f, r.rule.YieldsTo, spans, func(id string) bool { return reported[key(id, f.Path, f.Line)] }) {
			kept = append(kept, f)
		}
	}
	return kept
}

// yields reports whether every sink call f's rule reported f's line through
// overlaps one another rule of to reported it through.
func yields(f Finding, to []string, spans map[string]map[loc][]string, reported func(string) bool) bool {
	l := loc{f.Path, f.Line}
	own := spans[f.RuleID][l]
	if len(own) == 0 {
		return false
	}
	for _, s := range own {
		if s == "" {
			return false // a sink not written out here: it may be another one
		}
		taken := false
		for _, id := range to {
			if !reported(id) {
				continue
			}
			for _, o := range spans[id][l] {
				if o != "" && (strings.Contains(o, s) || strings.Contains(s, o)) {
					taken = true
				}
			}
		}
		if !taken {
			return false
		}
	}
	return true
}
