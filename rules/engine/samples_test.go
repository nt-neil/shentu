package engine

import (
	"fmt"
	"testing"

	"github.com/nt-neil/shentu/rules"
)

// TestSamples runs the engine on every sample of every rule: a vulnerable sample
// must be reported by its own rule, and a safe sample by no rule of its language.
func TestSamples(t *testing.T) {
	rs, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(rs)
	if err != nil {
		t.Fatal(err)
	}
	var vuln, vulnOK, safe, safeOK int
	for _, r := range rs {
		t.Run(r.ID, func(t *testing.T) {
			for i, s := range r.Samples {
				name := fmt.Sprintf("%s sample %d (%s)", r.File, i, s.Kind)
				fs, err := e.Scan(r.Lang, name, []byte(s.Code))
				if err != nil {
					t.Errorf("%s: %v", name, err)
				}
				switch s.Kind {
				case "vulnerable":
					vuln++
					found := false
					for _, f := range fs {
						found = found || f.RuleID == r.ID
					}
					if found {
						vulnOK++
					} else {
						t.Errorf("%s: not reported", name)
					}
				case "safe":
					safe++
					if len(fs) == 0 {
						safeOK++
					}
					for _, f := range fs {
						t.Errorf("%s: reported by %s at line %d", name, f.RuleID, f.Line)
					}
				}
			}
		})
	}
	t.Logf("vulnerable samples reported: %d/%d; safe samples clean: %d/%d", vulnOK, vuln, safeOK, safe)
}
