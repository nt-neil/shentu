// Package sample has one of each kind of site maprange lists or leaves out.
package sample

import (
	"maps"
	"slices"
)

type Project struct{ held map[string]bool }

func (p *Project) keep(f string)        { p.held[f] = true }
func (p *Project) shrink()              {}
func (p *Project) context(f string)     { p.keep(f) }
func (p *Project) analysisFor(f string) { p.context(f) }

func load(p *Project, f string) { p.analysisFor(f) }

func pure(f string) int { return len(f) }

type reader interface{ read(string) }

func walk(p *Project, m map[string]int, cb func(string), r reader) {
	for f := range m { // reaches through load
		load(p, f)
	}
	for f := range m { // reaches through a function value
		g := load
		g(p, f)
	}
	for f := range m { // a func parameter and an interface method
		cb(f)
		r.read(f)
	}
	for f := range m { // reaches nothing
		_ = pure(f)
	}
	keys := slices.Sorted(maps.Keys(m)) // sorted at once: not listed
	for _, f := range keys {            // a slice: not listed
		load(p, f)
	}
	_ = slices.Collect(maps.Values(m)) // listed
	for f := range maps.Keys(m) {      // listed once, as the range
		_ = f
	}
}
