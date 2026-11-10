package engine

import (
	"cmp"
	"slices"
)

// Cycles across files. Summaries are worked out on demand, inside one
// another, each in a budget of its own (own); a call back to a summary still
// being worked out further down closes a cycle. Within a file such cycles are
// known beforehand (components) and settled together; across files they are
// found on the way: the summary asked for counts as doing nothing for now,
// every summary from it up to the asker joins the cycle, and those finished
// before the first member are held, not kept. When the first member
// finishes, it settles the cycle: every member starts again from "does
// nothing" and all are worked out, in a fixed order (file, then key), until
// none changes. What comes out is the cycle's least fixed point, whichever
// member was asked for first; then all members are kept.

// sumFrame is a summary (or a file's cycle of summaries) being worked out.
type sumFrame struct {
	a       *analysis // the asker of its file: its summaries, budget, file
	keys    []string
	root    int // the lowest frame of a cycle this one is in; its own index when none
	members []sumMember
}

// sumMember is a summary of a cycle across files, finished before the cycle's first member.
type sumMember struct {
	a   *analysis
	key string
}

// heldSum is a member's summary until its cycle is settled.
type heldSum struct {
	s    *summary
	root int
}

// push records a summary being worked out and returns its frame's index (-1 outside a project).
func (p *Project) push(a *analysis, keys []string) int {
	if p == nil {
		return -1
	}
	p.stack = append(p.stack, &sumFrame{a: a, keys: keys, root: len(p.stack)})
	return len(p.stack) - 1
}

// pop ends the top frame; a frame in a cycle passes its cycle on to the one below.
func (p *Project) pop() *sumFrame {
	if p == nil || len(p.stack) == 0 {
		return nil
	}
	fr := p.stack[len(p.stack)-1]
	p.stack = p.stack[:len(p.stack)-1]
	if n := len(p.stack); n > 0 && fr.root < n {
		p.stack[n-1].root = min(p.stack[n-1].root, fr.root)
	}
	return fr
}

// frameOf is the index of the frame working out key of sc.
func (p *Project) frameOf(sc *summaries, key string) int {
	for i := len(p.stack) - 1; i >= 0; i-- {
		if fr := p.stack[i]; fr.a.sc == sc && slices.Contains(fr.keys, key) {
			return i
		}
	}
	return len(p.stack) // not on the stack (should not happen): no cycle
}

// cycleTo makes every frame from i up part of the cycle whose first member is frame i.
func (p *Project) cycleTo(i int) {
	for j := i; j < len(p.stack); j++ {
		p.stack[j].root = min(p.stack[j].root, i)
	}
}

// hold keeps a cycle member's summaries until the cycle is settled, and
// hands it, with the members it collected, to the cycle's first member.
func (p *Project) hold(fr *sumFrame, sums map[string]*summary) {
	if p.held == nil {
		p.held = map[*summaries]map[string]heldSum{}
	}
	if p.held[fr.a.sc] == nil {
		p.held[fr.a.sc] = map[string]heldSum{}
	}
	root := p.stack[fr.root]
	for k, s := range sums {
		p.held[fr.a.sc][k] = heldSum{s, fr.root}
		root.members = append(root.members, sumMember{fr.a, k})
	}
	root.members = append(root.members, fr.members...)
}

// provisional returns a held member's summary; whoever uses it joins its cycle.
func (p *Project) provisional(sc *summaries, key string) *summary {
	if p == nil {
		return nil
	}
	h, ok := p.held[sc][key]
	if !ok {
		return nil
	}
	p.cycleTo(h.root)
	return h.s
}

// settle works out the cycle whose first member is fr to its least fixed
// point and keeps every member; it returns key's summary of fr.
func (p *Project) settle(fr *sumFrame, key string) *summary {
	members := slices.Clone(fr.members)
	for _, k := range fr.keys {
		members = append(members, sumMember{fr.a, k})
	}
	slices.SortFunc(members, func(x, y sumMember) int {
		return cmp.Or(cmp.Compare(x.a.file, y.a.file), cmp.Compare(x.key, y.key))
	})
	members = slices.CompactFunc(members, func(x, y sumMember) bool { return x.a.sc == y.a.sc && x.key == y.key })
	for _, m := range members {
		delete(p.held[m.a.sc], m.key)
		m.a.sc.done[m.key] = &summary{} // the fixed point starts from "does nothing"
	}
	capped, height := false, 0
	for round := 0; ; round++ {
		changed := false
		for _, m := range members {
			var n *summary
			c, keep, h := m.a.own(func(x *analysis) { n = x.summarizeKey(m.key) })
			if !keep || n == nil { // the clock: nothing of the cycle is kept
				for _, m := range members {
					delete(m.a.sc.done, m.key)
				}
				return &summary{}
			}
			capped, height = capped || c, max(height, h)
			if !n.equal(m.a.sc.done[m.key]) {
				m.a.sc.done[m.key], changed = n, true
			}
		}
		if !changed {
			break
		}
		if round+1 >= maxSumRounds {
			capped = true // a cycle that does not settle
			break
		}
	}
	for _, m := range members {
		m.a.sc.done[m.key].capped, m.a.sc.done[m.key].height = capped, height
	}
	return fr.a.sc.done[key]
}

// drop forgets the members a frame collected, when its cycle cannot be
// settled (the clock): they are worked out again when asked.
func (p *Project) drop(fr *sumFrame) {
	if p == nil || fr == nil {
		return
	}
	for _, m := range fr.members {
		delete(p.held[m.a.sc], m.key)
	}
}
