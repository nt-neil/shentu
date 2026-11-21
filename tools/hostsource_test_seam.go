package tools

import "github.com/nt-neil/shentu/hostenv"

// SetHostSourceForTest makes every tool read src (a fixture's replay) and
// returns how to undo it. For other packages' tests only (the patrol's
// checks on a macOS fixture): the product never calls it, and a call from
// product code is a blocking review finding (TestSetHostSourceForTestOnlyInTests).
func SetHostSourceForTest(src hostenv.Source) (restore func()) {
	old := hostSource
	hostSource = func() hostenv.Source { return src }
	return func() { hostSource = old }
}
