package hostenv

import (
	"runtime"
	"strings"
	"testing"
)

// fanoutBplist builds a binary plist {Label: "com.example.fan",
// ProgramArguments: [s, s, ... n times]} where s is one string of size bytes.
func fanoutBplist(n, size int) []byte {
	b := []byte("bplist00")
	var offs []int
	obj := func(o []byte) { offs = append(offs, len(b)); b = append(b, o...) }
	ascii := func(s string) []byte {
		if len(s) < 15 {
			return append([]byte{0x50 | byte(len(s))}, s...)
		}
		return append([]byte{0x5f, 0x12, byte(len(s) >> 24), byte(len(s) >> 16), byte(len(s) >> 8), byte(len(s))}, s...)
	}
	// 0 dict, 1 "Label", 2 "ProgramArguments", 3 label value, 4 array, 5 the long string
	obj([]byte{0xd2, 0, 1, 0, 2, 0, 3, 0, 4})
	obj(ascii("Label"))
	obj(ascii("ProgramArguments"))
	obj(ascii("com.example.fan"))
	arr := []byte{0xaf, 0x12, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	for i := 0; i < n; i++ {
		arr = append(arr, 0, 5)
	}
	obj(arr)
	obj(ascii(strings.Repeat("A", size)))
	table := len(b)
	for _, o := range offs {
		b = append(b, byte(o>>8), byte(o))
	}
	t := make([]byte, 32)
	t[6], t[7] = 2, 2
	put := func(at, v int) {
		for k := 0; k < 8; k++ {
			t[at+7-k] = byte(v >> (8 * k))
		}
	}
	put(8, len(offs))
	put(16, 0)
	put(24, table)
	return append(b, t...)
}

// fakeMacDirs is fakeMac with directory listings.
type fakeMacDirs struct {
	fakeMac
	dirs map[string][]string
}

func (f fakeMacDirs) ReadDir(p string) ([]string, error) {
	if l, ok := f.dirs[p]; ok {
		return l, nil
	}
	return nil, &notExist{p}
}

// An 18 KB plist that repeats one 8 KB argument 5000 times by reference
// (40 MB once joined) is cut at maxLaunchArgs / MaxCmdline, marked
// partial, and costs little memory.
func TestLaunchdArgumentsCapped(t *testing.T) {
	b := fanoutBplist(5000, 8000)
	if len(b) > 18<<10 {
		t.Fatalf("plist is %d bytes", len(b))
	}
	src := fakeMacDirs{fakeMac: fakeMac{files: map[string]string{"/Library/LaunchDaemons/fan.plist": string(b)}},
		dirs: map[string][]string{"/Library/LaunchDaemons": {"fan.plist"}}}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	o, jobs := DarwinCollector{}.Services(src, OK([]Account(nil)))
	runtime.ReadMemStats(&after)
	if n := after.TotalAlloc - before.TotalAlloc; n > 2<<20 {
		t.Errorf("allocated %d bytes", n)
	}
	if len(jobs) != 1 || len(jobs[0].program) > MaxCmdline+len("…") || jobs[0].label != "com.example.fan" {
		t.Fatalf("%d jobs, program %d bytes", len(jobs), len(jobs[0].program))
	}
	if o.Status != StatusPartial || !strings.Contains(o.Detail, "ProgramArguments cut") {
		t.Errorf("%s %q", o.Status, o.Detail)
	}
	// Few short arguments are kept whole.
	prog, cut := launchProgram(map[string]any{"ProgramArguments": []any{"/usr/local/bin/x", "--daily"}})
	if prog != "/usr/local/bin/x --daily" || cut {
		t.Errorf("%q %v", prog, cut)
	}
	many := make([]any, 100)
	for i := range many {
		many[i] = "a"
	}
	if prog, cut := launchProgram(map[string]any{"ProgramArguments": many}); !cut || strings.Count(prog, "a") != maxLaunchArgs {
		t.Errorf("100 arguments: %d kept, cut %v", strings.Count(prog, "a"), cut)
	}
}

// A binary plist with more array entries than maxPlistElems is refused.
func TestBplistElementCap(t *testing.T) {
	if _, err := ParsePlist(fanoutBplist(maxPlistElems+1, 1)); err == nil || !strings.Contains(err.Error(), "too many elements") {
		t.Errorf("err %v", err)
	}
	if _, err := ParsePlist(fanoutBplist(1000, 1)); err != nil {
		t.Errorf("1000 entries: %v", err)
	}
}
