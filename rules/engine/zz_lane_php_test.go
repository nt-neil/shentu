package engine

import (
	"os"
	"strings"
	"testing"
)

func TestLanePHPProbe(t *testing.T) {
	e := engineForTest(t)
	b, _ := os.ReadFile(os.Getenv("PROBE"))
	for _, src := range strings.Split(string(b), "\n=====\n") {
		fs, err := e.Scan("php", "t.php", []byte(src))
		ids := []string{}
		for _, f := range fs {
			ids = append(ids, f.RuleID)
		}
		t.Logf("%v %v <- %q", ids, err, src)
	}
}
