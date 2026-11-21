package engine

import (
	"errors"
	"strings"
)

// Cut says what cut a scan short. A scan returning ErrLimit or ErrCalls
// returns them inside a *CutError naming the causes (errors.Is still finds
// ErrLimit or ErrCalls); CutOf reads them back.
type Cut uint16

const (
	CutTokens    Cut = 1 << iota // the file's token cap (Limits.MaxTokens)
	CutTime                      // the file's clock (Limits.MaxTime): depends on the machine
	CutNesting                   // nesting too deep: read flat or skipped
	CutCallWork                  // a rule's work cap for following calls (Limits.MaxCallWork)
	CutSummary                   // a callee's summary hit its cap and may say too little
	CutProject                   // the project's cap (its clock, heap or tokens): calls stopped crossing files
	CutCallDepth                 // calls nested deeper than summaries are worked out (maxOwnNest, maxSumDepth)
	CutCycle                     // a recursive cycle whose summaries did not settle (maxSumRounds)
	CutParams                    // a function with more parameters than a summary tracks (maxSumParams)
	CutAmbiguous                 // a call that may reach another file, with no one callee to follow
	// Why a summary used was capped (CutSummary with one or more of these):
	CutSumWork   // its own work cap (the budget's sumWork)
	CutSumHeight // a chain of summaries under it longer than maxSumHeight
	CutSumParams // more parameters than it tracks
	CutSumInner  // something inside it nested too deep
)

var cutNames = []string{"tokens", "time", "nesting", "call-work", "summary", "project", "call-depth", "cycle", "params", "ambiguous-call", "summary-work", "summary-height", "summary-params", "summary-inner"}

// String names the causes, comma-separated, in a fixed order.
func (c Cut) String() string {
	var b []string
	for i, n := range cutNames {
		if c&(1<<i) != 0 {
			b = append(b, n)
		}
	}
	return strings.Join(b, ",")
}

// Names lists the causes, in the order String gives them.
func (c Cut) Names() []string {
	if c == 0 {
		return nil
	}
	return strings.Split(c.String(), ",")
}

// CutError is ErrLimit or ErrCalls with what caused it.
type CutError struct {
	Err error // ErrLimit or ErrCalls
	Cut Cut
}

func (e *CutError) Error() string { return e.Err.Error() }
func (e *CutError) Unwrap() error { return e.Err }

// CutOf returns the causes err names (0 for none, or for another error).
func CutOf(err error) Cut {
	var c *CutError
	if errors.As(err, &c) {
		return c.Cut
	}
	return 0
}

// cutErr wraps err (ErrLimit or ErrCalls) with its causes.
func cutErr(err error, c Cut) error { return &CutError{Err: err, Cut: c} }

// cut is what cut a budget short: tokens, work cap, clock or nesting.
func (b *budget) cut() Cut {
	if b == nil {
		return 0
	}
	var c Cut
	if b.tokens > b.maxTok {
		c |= CutTokens
	}
	if b.timeHit {
		c |= CutTime
	}
	if b.limited {
		c |= b.deep
		if b.deep == 0 && !b.hit {
			c |= CutNesting // a hit budget also stops reading summaries (tooDeep): its cause is the hit's
		}
	}
	if b.hit && b.maxWork > 0 && b.work > b.maxWork {
		c |= CutCallWork
	}
	return c
}

// callsCutOf is what cut the calls pass's budget b2 short. In a project its
// clock is the project's (scan: b2.deadline = proj.deadline), so running out
// of time there is the project's cap, not the file's time limit.
func callsCutOf(b2 *budget, proj *Project) Cut {
	c := b2.cut()
	if proj != nil && c&CutTime != 0 {
		c = c&^CutTime | CutProject
	}
	return c
}
