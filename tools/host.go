package tools

import (
	"runtime"

	"github.com/nt-neil/shentu/hostenv"
)

// Tools reach the machine through hostenv (Phase 1c): hostSource is the
// live host, and tests replace it with a fixture replay or a fake.
var hostSource = func() hostenv.Source {
	l, err := hostenv.NewLive(hostenv.ForOS(runtime.GOOS).Allowlist())
	if err != nil {
		panic(err) // the allowlist is a constant; a bad one is a programming error
	}
	return l
}

var linux hostenv.LinuxCollector

// hostPlatform is the platform fact and the parsed os-release (nil when
// unreadable).
func hostPlatform() (hostenv.Platform, map[string]string) {
	p, osr := linux.Platform(hostSource())
	return p.Value, osr
}
