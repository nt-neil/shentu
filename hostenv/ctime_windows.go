package hostenv

import (
	"io/fs"
	"time"
)

// statWinNA are the stat fields Windows has none of as Unix means them:
// owner and group are SIDs (FileSecurity), and the checks that use ctime
// and nlink are Unix's.
var statWinNA = []string{"uid", "gid", "ctime", "nlink"}

// statExtra on Windows: ctime and nlink do not apply.
func statExtra(fs.FileInfo) (*time.Time, *uint64, []string) {
	return nil, nil, append([]string(nil), statWinNA...)
}
