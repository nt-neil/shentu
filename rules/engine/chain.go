package engine

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
		if len(t) != 4 || t[0].Kind != Ident || !memberOp(php, t[1]) || t[1].Text == "?->" || t[2].Kind != Ident || !t[3].op("(") || s.chain != "" {
			continue
		}
		op := "."
		if php {
			op = "->" // after a static or an instance call, PHP chains with ->
		}
		m := &pat{raw: op + t[2].Text + "(", php: php, member: true, name: t[2].Text, chain: t[0].Text,
			toks: []Token{{Kind: Op, Text: op}, t[2], t[3]}}
		c.sinks = append(c.sinks, m)
		if cond, ok := c.args[s]; ok {
			c.args[m] = cond
		}
		if more, ok := c.argsMore[s]; ok {
			if c.argsMore == nil {
				c.argsMore = map[*pat][]*argCond{}
			}
			c.argsMore[m] = more
		}
	}
}

// chainFrom reports whether the member operator at toks[i] ends a chain of
// calls that starts at the receiver cls: cls::a(...)->b(...)->, cls.a(...).b(...).
func chainFrom(toks []Token, i int, cls string) bool {
	php := toks[i].Text == "->"
	j := i - 1
	for steps := 0; j >= 1 && steps < 32; steps++ {
		if !toks[j].op(")") {
			return false
		}
		open := openOf(toks, j)
		if open < 2 || toks[open-1].Kind != Ident || !memberOp(php, toks[open-2]) {
			return false
		}
		j = open - 3 // the receiver of this call
		switch {
		case j < 0:
			return false
		case toks[j].word(cls) || toks[j].Kind == Var && toks[j].Text == cls:
			return j == 0 || !memberOp(php, toks[j-1]) // cls itself, not x.cls
		case !toks[j].op(")"):
			return false
		}
	}
	return false
}
