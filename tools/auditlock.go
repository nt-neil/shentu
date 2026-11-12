package tools

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/nt-neil/shentu/internal/osutil"
)

// One code audit runs at a time, in this process and across processes (the
// bot, the patrol and the CLI): each sets Go's memory limit and takes the
// memory budget for itself, and each writes the code index and the kept
// results. A second audit waits for the first one; it is not refused.
var auditSlot = make(chan struct{}, 1)

// auditLockPoll is how often a waiting audit tries the lock of another process.
var auditLockPoll = 100 * time.Millisecond

// auditLockWait is the longest an audit waits for another one, for a caller
// without a time limit of its own (the patrol): an audit holds the turn for
// about injectionMaxTime, so this outlasts one.
var auditLockWait = 3 * time.Minute

// lockAudit waits for the audit slot and the lock file next to the code index
// ("" for none: the slot alone). It fails only when ctx ends first.
func lockAudit(ctx context.Context) (unlock func(), err error) {
	ctx, cancel := context.WithTimeout(ctx, auditLockWait)
	defer cancel()
	select {
	case auditSlot <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	release := func() { <-auditSlot }
	idx := codeIndexFile()
	if idx == "" || os.MkdirAll(filepath.Dir(idx), 0o700) != nil {
		return release, nil
	}
	f, err := osutil.OpenNoFollow(filepath.Join(filepath.Dir(idx), "audit.lock"), os.O_RDWR|os.O_CREATE, 0o600, false)
	if err != nil {
		return release, nil // the lock is for the shared files; without it the audit still runs
	}
	for {
		err := osutil.TryLock(f)
		if err == nil {
			break
		}
		if !errors.Is(err, osutil.ErrWouldBlock) {
			f.Close() // a file system without locks: the slot alone
			return release, nil
		}
		select {
		case <-ctx.Done():
			f.Close()
			release()
			return nil, ctx.Err()
		case <-time.After(auditLockPoll):
		}
	}
	return func() {
		osutil.Unlock(f)
		f.Close()
		release()
	}, nil
}
