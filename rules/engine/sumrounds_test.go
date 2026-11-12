package engine

import "testing"

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
