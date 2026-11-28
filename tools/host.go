package tools

import (
	"reflect"
	"runtime"

	"github.com/nt-neil/shentu/hostenv"
)

// Tools reach the machine through hostenv (Phase 1c): hostSource is the
// live host, and tests replace it with a fixture replay or a fake.
var hostSource = liveHostSource

func liveHostSource() hostenv.Source {
	l, err := hostenv.NewLive(hostenv.ForOS(runtime.GOOS).Allowlist())
	if err != nil {
		panic(err) // the allowlist is a constant; a bad one is a programming error
	}
	return l
}

// hostIsLive: the host read is this machine (hostSource not replaced by a
// replay or a test). Asked for every file a scan reads (onWindows,
// hostPaths), so it answers without making a Live.
func hostIsLive() bool {
	return reflect.ValueOf(hostSource).Pointer() == reflect.ValueOf(liveHostSource).Pointer()
}

var linux hostenv.LinuxCollector

// hostPlatform is the platform fact and the parsed os-release (nil when
// unreadable).
func hostPlatform() (hostenv.Platform, map[string]string) {
	p, osr := linux.Platform(hostSource())
	return p.Value, osr
}
