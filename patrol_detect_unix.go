//go:build !windows

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// ownDir: st, a directory of the state's, is this process's user's.
func ownDir(st os.FileInfo) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(s.Uid) == os.Geteuid()
}

// detectStateDir makes sure dir can hold attack detection's state before
// `shentu detect` takes its lock: a fresh host's first run as root makes
// it (0700, this user's); otherwise it says what to do rather than
// failing on the lock file's open.
func detectStateDir(dir string, root bool) error {
	st, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if !root {
			return fmt.Errorf("狀態目錄 %s 不存在：第一次執行 shentu detect 需要 root（sudo shentu detect），或在設定檔以 state_dir 指定一個自己可寫的目錄", dir)
		}
		if err := ensureStateDir(dir); err != nil {
			return fmt.Errorf("無法建立狀態目錄 %s：%w", dir, err)
		}
		st, err = os.Lstat(dir)
	}
	if err != nil {
		return fmt.Errorf("無法讀取狀態目錄 %s：%w", dir, err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() || !ownDir(st) || st.Mode().Perm()&0o022 != 0 {
		if !root && !ownDir(st) {
			return fmt.Errorf("狀態目錄 %s 不屬於目前的使用者：請用 root 執行（sudo shentu detect），或在設定檔以 state_dir 指定一個自己可寫的目錄", dir)
		}
		return fmt.Errorf("狀態目錄 %s 不是目前使用者自己的一般目錄（連結、他人擁有，或群組／其他人可寫）：攻擊偵測不使用它", dir)
	}
	return nil
}
