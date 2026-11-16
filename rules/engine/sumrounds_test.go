package engine

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// A recursive cycle settles when what its members return stops changing; each
// round can carry a parameter only a step or two further round the cycle. Here
// f1 and f2 call each other and pass their twelve parameters on rotated by
// one, so the second reaches the return value only after about six rounds: the
// cycle must be followed until it settles, not cut after a fixed few rounds
// (WordPress's rest_validate_value_from_schema and the six functions it calls
// in a ring settle in five).
func TestCycleSettles(t *testing.T) {
	e := engineForTest(t)
	src := `<?php
function f1($p0, $p1, $p2, $p3, $p4, $p5, $p6, $p7, $p8, $p9, $p10, $p11) {
	$n = intval($p2);
	if (rand()) {
		return $p0;
	}
	return f2($p11, $p0, $p1, $p2, $p3, $p4, $p5, $p6, $p7, $p8, $p9, $p10);
}
function f2($p0, $p1, $p2, $p3, $p4, $p5, $p6, $p7, $p8, $p9, $p10, $p11) {
	$n = intval($p2);
	if (rand()) {
		return $p0;
	}
	return f1($p11, $p0, $p1, $p2, $p3, $p4, $p5, $p6, $p7, $p8, $p9, $p10);
}
echo f1(0, $_GET['x'], 2, 3, 4, 5, 6, 7, 8, 9, 10, 11);
`
	fs, err := e.Scan("php", "a.php", []byte(src))
	if err != nil || len(fs) == 0 {
		t.Errorf("findings %v, err %v; want the echo reported and the cycle followed to the end", fs, err)
	}
}

// The functions of a cycle are worked out together, at one cost: an asker
// using several of them pays it once, not once for each. Six functions
// calling each other in a ring must need about the work of the same six
// called in a chain, not six times it (WordPress's
// rest_filter_response_by_context, using six functions of a seven-function
// ring, paid the ring seven times and ran out of its work cap).
func TestCycleCostOnce(t *testing.T) {
	file := func(back bool) string {
		var b strings.Builder
		b.WriteString("<?php\n")
		for i := 1; i <= 6; i++ {
			next := fmt.Sprintf("f%d($p)", i+1)
			if i == 6 {
				next = "$p"
				if back {
					next = "f1($p)"
				}
			}
			fmt.Fprintf(&b, "function f%d($p) {\n\t$n = intval($p);\n\tif (rand()) {\n\t\treturn trim(strtolower(str_replace('a', 'b', $p)));\n\t}\n\treturn %s;\n}\n", i, next)
		}
		b.WriteString("echo f1($_GET['a']);\n")
		return b.String()
	}
	need := func(src string) int {
		e := engineForTest(t)
		for work := 1000; work < 1<<30; work += work / 4 {
			e.Limits = Limits{MaxTokens: DefaultLimits.MaxTokens, MaxTime: time.Minute, MaxCallWork: work}
			if _, err := e.Scan("php", "a.php", []byte(src)); err == nil {
				return work
			}
		}
		t.Fatal("never followed to the end")
		return 0
	}
	chain, ring := need(file(false)), need(file(true))
	t.Logf("work needed: chain %d, ring %d", chain, ring)
	if ring > 4*chain {
		t.Errorf("the ring needed %d, the chain %d: the ring's cost paid once for each function", ring, chain)
	}
}
