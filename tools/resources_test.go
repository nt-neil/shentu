package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSystem points the budget at a made-up /proc and /sys/fs/cgroup.
func fakeSystem(t *testing.T, files map[string]string) {
	t.Helper()
	root := t.TempDir()
	for p, c := range files {
		full := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pd, cd := procDir, cgroupDir
	procDir, cgroupDir = filepath.Join(root, "proc"), filepath.Join(root, "cgroup")
	t.Cleanup(func() { procDir, cgroupDir = pd, cd; SetAuditLimits(0, 0) })
}

const (
	mib    = 1 << 20
	unit   = "proc/self/cgroup"
	svc    = "cgroup/system.slice/shentu-patrol.service/"
	vps2gb = "MemTotal:        2014000 kB\nMemAvailable:    1600000 kB\n"
)

func TestAuditBudget(t *testing.T) {
	if runtime.NumCPU() < 8 || runtime.GOMAXPROCS(0) < 8 {
		t.Skip("needs 8 CPUs to stand for the 8-core machine")
	}
	v2 := "0::/system.slice/shentu-patrol.service\n"
	cases := []struct {
		name          string
		files         map[string]string
		memMB, workMB int // overrides
		heap, limit   uint64
		workers       int
	}{
		{"2 GB, 2 cores", map[string]string{"proc/meminfo": vps2gb, "proc/loadavg": "0.30 0.2 0.1 1/90 9\n", unit: v2,
			svc + "cpu.max": "200000 100000\n", svc + "memory.max": "max\n"}, 0, 0, 400000 << 10, 800000 << 10, 1},
		{"8 GB, 8 cores", map[string]string{"proc/meminfo": "MemAvailable:    6500000 kB\n", unit: v2,
			svc + "cpu.max": "800000 100000\n"}, 0, 0, 1 << 30, 2 << 30, 4},
		{"systemd MemoryMax=512M", map[string]string{"proc/meminfo": "MemAvailable:    6500000 kB\n", unit: v2,
			svc + "memory.max": "536870912\n", "cgroup/system.slice/memory.max": "max\n"}, 0, 0, 256 * mib, 384 * mib, 4},
		{"a parent cgroup's limit counts", map[string]string{unit: v2, "cgroup/system.slice/memory.max": "268435456\n",
			svc + "memory.max": "max\n"}, 0, 0, 128 * mib, 192 * mib, 4},
		{"configured memory stays under MemoryMax", map[string]string{unit: v2, svc + "memory.max": "536870912\n"},
			2048, 0, 256 * mib, 384 * mib, 4},
		{"configured memory without a cgroup", map[string]string{"proc/meminfo": vps2gb}, 300, 0, 300 * mib, 600 * mib, 4},
		{"configured workers stay under CPUQuota", map[string]string{unit: v2, svc + "cpu.max": "200000 100000\n"},
			0, 8, 1 << 30, 2 << 30, 2},
		{"load above the CPUs", map[string]string{unit: v2, svc + "cpu.max": "200000 100000\n", "proc/loadavg": "2.50 1 1 1/90 9\n"},
			0, 2, 1 << 30, 2 << 30, 1},
		{"cgroup v1", map[string]string{"proc/self/cgroup": "5:memory:/shentu\n4:cpu,cpuacct:/shentu\n",
			"cgroup/memory/shentu/memory.limit_in_bytes": "1073741824\n", "cgroup/memory/memory.limit_in_bytes": "9223372036854771712\n",
			"cgroup/cpu,cpuacct/shentu/cpu.cfs_quota_us": "150000\n", "cgroup/cpu,cpuacct/shentu/cpu.cfs_period_us": "100000\n"},
			0, 0, 512 * mib, 768 * mib, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fakeSystem(t, c.files)
			SetAuditLimits(c.memMB, c.workMB)
			b := currentBudget()
			if b.heap != c.heap || b.limit != c.limit || b.workers != c.workers {
				t.Errorf("budget %+v (heap %d MiB, limit %d MiB), want heap %d MiB, limit %d MiB, workers %d",
					b, b.heap/mib, b.limit/mib, c.heap/mib, c.limit/mib, c.workers)
			}
		})
	}
}

// Under a cgroup limit of 512 MB the whole audit, the process included, stays
// within it: calls stop crossing files at the heap budget, the GC is held to
// the soft limit, and the audit still says how far it got.
func TestAuditMemoryUnderCgroup(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and scans a large project")
	}
	fakeSystem(t, map[string]string{unit: "0::/shentu.service\n", "cgroup/shentu.service/memory.max": "536870912\n"})
	dir := t.TempDir()
	writeLargeProject(t, dir, 1200, 60)
	runtime.GC()

	var peak atomic.Uint64
	done := make(chan struct{})
	go func() {
		s := []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}}
		for {
			metrics.Read(s)
			if used := s[0].Value.Uint64() - s[1].Value.Uint64(); used > peak.Load() {
				peak.Store(used)
			}
			select {
			case <-done:
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()
	max := injectionMaxTime
	injectionMaxTime = 10 * time.Minute // the memory cap, not the time cap, is what this test is about
	defer func() { injectionMaxTime = max }()
	res := AppCodeAudit(context.Background(), []string{dir}, nil)
	close(done)

	if p := peak.Load(); p > 512*mib {
		t.Errorf("memory in use peaked at %d MiB, over the 512 MiB cgroup limit", p/mib)
	} else {
		t.Logf("memory in use peaked at %d MiB", p/mib)
	}
	var cross string
	for _, f := range res.Findings {
		if f.Kind == "injection" && strings.Contains(f.Detail, "calls across files") {
			cross = f.Detail
		}
	}
	if !strings.Contains(cross, "memory limit") {
		t.Errorf("want the summary to say calls stopped at the memory limit, got %q", cross)
	}
}

// writeLargeProject writes n PHP files of m methods each; every method passes
// request input on to a method of the next file, so following calls keeps
// many files parsed and summarised at once.
func writeLargeProject(t *testing.T, dir string, n, m int) {
	t.Helper()
	for i := range n {
		var b strings.Builder
		fmt.Fprintf(&b, "<?php\nclass C%d {\n", i)
		for j := range m {
			fmt.Fprintf(&b, "  static function m%d($a, $b) {\n    $x = trim($a) . '-' . $b;\n    $y = strtolower($x);\n"+
				"    if ($y == 'q%d') { return C%d::m%d($y, $b); }\n    mysqli_query($db, \"SELECT * FROM t%d WHERE c = '$y'\");\n"+
				"    return C%d::m%d($x, $_GET['k%d']);\n  }\n", j, j, (i+1)%n, (j+1)%m, j, (i+1)%n, j, j)
		}
		b.WriteString("}\n")
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("c%d.php", i)), []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
