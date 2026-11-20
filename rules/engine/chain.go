package engine

import (
	"maps"
	"slices"
	"strings"
)

// A call is often made through a chain on the same receiver: PHP facades
// (Process::timeout(30)->run($cmd)), Express responses (res.status(400).send(x)),
// client sessions (requests.Session().get(url)). A sink written as receiver,
// member and method (Process::run(, res.send(, requests.get() is matched there
// too: for each such sink the rule also has its chain form (->run(, .send(,
// .get(), which matches only at the end of a chain of calls that starts at the
// same receiver. The rule engine and the rule lanes share this for every
// language.

// chainSinks makes the chain form of a rule's receiver.method( sinks, with the
// same argument conditions.
func (c *crule) chainSinks() {
	php := c.rule.Lang == "php"
	for _, s := range c.sinks {
		t := s.toks
		if m := viaSink(s); m != nil {
			c.sinks = append(c.sinks, m)
			if cond, ok := c.args[s]; ok {
				c.args[m] = cond
			}
			if more, ok := c.argsMore[s]; ok {
				c.argsMore[m] = more
			}
			continue
		}
		if len(t) != 4 || t[0].Kind != Ident || !memberOp(php, t[1]) || t[1].Text == "?->" || t[2].Kind != Ident || !t[3].op("(") || s.chain != "" {
			continue
		}
		op := "."
		if php {
			op = "->" // after a static or an instance call, PHP chains with ->
		}
		m := &pat{raw: op + t[2].Text + "(", php: php, member: true, name: t[2].Text, chain: t[0].Text,
			toks: []Token{{Kind: Op, Text: op}, t[2], t[3]}}
		if len(c.rule.ChainNot) > 0 {
			m.chainNot = map[string]bool{}
			for _, n := range c.rule.ChainNot {
				m.chainNot[n] = true
			}
		}
		c.sinks = append(c.sinks, m)
		if cond, ok := c.args[s]; ok {
			c.args[m] = cond
		}
		if more, ok := c.argsMore[s]; ok { // ok only where argsMore is not nil
			c.argsMore[m] = more
		}
	}
}

// viaSink makes the chain form of a sink written receiver.Maker(*).method(
// (httpx.Client(*).get(): .get( at the end of a chain that starts at the
// receiver and goes through a call to Maker, with any arguments
// (httpx.Client(timeout=5).get(u)). Nil for any other sink.
func viaSink(s *pat) *pat {
	t := s.toks
	if len(t) != 9 || t[0].Kind != Ident || !memberOp(s.php, t[1]) || t[2].Kind != Ident || !t[3].op("(") || !t[4].op("*") ||
		!t[5].op(")") || !memberOp(s.php, t[6]) || t[7].Kind != Ident || !t[8].op("(") {
		return nil
	}
	return &pat{raw: s.raw, php: s.php, member: true, name: t[7].Text, chain: t[0].Text, chainVia: t[2].Text,
		toks: []Token{t[6], t[7], t[8]}}
}

// chainKey tells chain forms with the same raw apart in a file's sink cache:
// the receiver, the call they must go through, and the calls they may not.
func (p *pat) chainKey() string {
	if p.chain == "" {
		return ""
	}
	not := slices.Sorted(maps.Keys(p.chainNot))
	return p.chain + "\x00" + p.chainVia + "\x00" + strings.Join(not, ",")
}

// chainFrom reports whether the member operator at toks[i] ends a chain of
// calls that starts at the receiver cls: cls::a(...)->b(...)->, cls.a(...).b(...).
// A call named in not makes another object, which the chain may not go
// through: httpx.AsyncClient().get( is a client's, not httpx's.
// With via, the chain must go through a call to via.
func chainFrom(toks []Token, i int, cls, via string, not map[string]bool) bool {
	php := toks[i].Text == "->"
	j := i - 1
	passed := via == ""
	for steps := 0; j >= 1 && steps < 32; steps++ {
		if !toks[j].op(")") {
			return false
		}
		open := openOf(toks, j)
		if open < 2 || toks[open-1].Kind != Ident || !memberOp(php, toks[open-2]) || not[toks[open-1].Text] {
			return false
		}
		passed = passed || toks[open-1].Text == via
		j = open - 3 // the receiver of this call
		switch {
		case j < 0:
			return false
		case toks[j].word(cls) || toks[j].Kind == Var && toks[j].Text == cls:
			return passed && (j == 0 || !memberOp(php, toks[j-1])) // cls itself, not x.cls
		case !toks[j].op(")"):
			return false
		}
	}
	return false
}
