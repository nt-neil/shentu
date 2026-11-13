// Package checks holds Shentu's platform-independent host checks. A check
// reads hostenv.Facts and nothing else: no files, no commands, no runtime.GOOS.
// That is what lets one check cover Linux, Windows and every later collector.
//
// A fact that is unknown produces a finding with StatusCannotTell, never
// silence: "we could not look" must not read as "nothing is wrong".
package checks

import (
	"sort"

	"github.com/nt-neil/shentu/hostenv"
)

type Severity string

const (
	SevHigh   Severity = "high"
	SevMedium Severity = "medium"
	SevLow    Severity = "low"
	SevInfo   Severity = "info"
)

type Status string

const (
	StatusFail       Status = "fail"        // the risk is present
	StatusCannotTell Status = "cannot_tell" // the facts needed were unknown (無法判斷)
)

type Finding struct {
	Check    string   `json:"check"`
	Status   Status   `json:"status"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Evidence string   `json:"evidence,omitempty"`
	Reason   string   `json:"reason,omitempty"` // for cannot_tell: the fact's reason
}

// Check is one rule over facts.
type Check interface {
	ID() string
	Run(f *hostenv.Facts) []Finding
}

// All is every registered check, in a stable order.
func All() []Check {
	cs := append([]Check(nil), registry...)
	sort.Slice(cs, func(i, j int) bool { return cs[i].ID() < cs[j].ID() })
	return cs
}

var registry []Check

func register(c Check) { registry = append(registry, c) }

// Run applies every check to f.
func Run(f *hostenv.Facts) []Finding {
	var out []Finding
	for _, c := range All() {
		out = append(out, c.Run(f)...)
	}
	return out
}

// cannotTell is the finding for an observation a check depends on but could
// not see. Not-applicable facts produce nothing: there is no RDP on Linux.
func cannotTell[T any](id, title string, o hostenv.Obs[T]) []Finding {
	if o.Status != hostenv.StatusUnknown && o.Status != hostenv.StatusError {
		return nil
	}
	return []Finding{{Check: id, Status: StatusCannotTell, Severity: SevInfo, Title: title,
		Reason: string(o.Reason), Evidence: o.Detail}}
}

// partialNote is the cannot_tell finding for an observation that is usable
// but incomplete: what was seen is judged, what was hidden is admitted.
func partialNote[T any](id, title string, o hostenv.Obs[T]) []Finding {
	if o.Status != hostenv.StatusPartial {
		return nil
	}
	return []Finding{{Check: id, Status: StatusCannotTell, Severity: SevInfo, Title: title,
		Reason: string(o.Reason), Evidence: o.Detail}}
}

// checkFunc adapts a function to Check.
type checkFunc struct {
	id  string
	run func(*hostenv.Facts) []Finding
}

func (c checkFunc) ID() string                     { return c.id }
func (c checkFunc) Run(f *hostenv.Facts) []Finding { return c.run(f) }
