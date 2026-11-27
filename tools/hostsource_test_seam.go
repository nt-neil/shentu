package tools

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

// SetHostSourceForTest makes every tool read src (a fixture's replay) and
// returns how to undo it. For other packages' tests only (the patrol's
// checks on a macOS fixture): the product never calls it, and a call from
// product code is a blocking review finding (TestSetHostSourceForTestOnlyInTests).
func SetHostSourceForTest(src hostenv.Source) (restore func()) {
	old := hostSource
	hostSource = func() hostenv.Source { return src }
	return func() { hostSource = old }
}

// SetLoginIndexForTest keeps the login index in dir, as on a host whose
// journald shows this process every unit's entries, and returns how to undo
// it. For other packages' tests only (the patrol's refresh of the index),
// under the same rule as SetHostSourceForTest.
func SetLoginIndexForTest(dir string) (restore func()) {
	oldDir, oldKeep, oldAll := attackStateDir, KeepLoginIndex, journalAll
	attackStateDir, KeepLoginIndex = dir, true
	journalAll = func() bool { return true }
	return func() { attackStateDir, KeepLoginIndex, journalAll = oldDir, oldKeep, oldAll }
}

// SetSitePackagesForTest makes app_vulns take globs as the system's
// site-packages (none: the test machine's Python is not read), and Docker's
// and containerd's stores as paths that are not there (the test machine's
// images are not read either, whoever runs the test), and returns how to
// undo it. For other packages' tests only, under the same rule as
// SetHostSourceForTest.
func SetSitePackagesForTest(globs []string) (restore func()) {
	old, oldR, oldJ, oldC := systemSitePackages, dockerRoot, dockerDaemonJSON, containerdRoot
	none := filepath.Join(os.TempDir(), fmt.Sprintf("shentu-test-no-store-%d-%d", os.Getpid(), time.Now().UnixNano()))
	systemSitePackages = globs
	dockerRoot, dockerDaemonJSON, containerdRoot = filepath.Join(none, "docker"), filepath.Join(none, "daemon.json"), filepath.Join(none, "containerd")
	return func() { systemSitePackages, dockerRoot, dockerDaemonJSON, containerdRoot = old, oldR, oldJ, oldC }
}
