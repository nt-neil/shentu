package tools

import "github.com/nt-neil/shentu/hostenv"

// linuxLive is a Live source that says it is Linux: a Linux host built in a
// temporary directory, read the same way on a Mac (where Live says darwin).
type linuxLive struct{ *hostenv.Live }

func (l linuxLive) Info() hostenv.SourceInfo {
	i := l.Live.Info()
	i.GOOS = "linux"
	return i
}
