package tools

import (
	"runtime"

	"github.com/nt-neil/shentu/hostenv"
)

// Shentu runs on the customer's production server, so app_code_audit sizes
// itself to the machine: on a small VPS it must not slow the sites down or
// get the process killed for memory.

// auditBudget is what one audit may use.
type auditBudget struct {
	heap    uint64 // heap in use past which calls stop crossing files
	limit   uint64 // Go's soft memory limit while the audit runs: the budget itself (the GC works harder near it)
	workers int    // files scanned at once
}

// The system files read, replaced in tests.
var (
	procDir   = "/proc"
	cgroupDir = "/sys/fs/cgroup"
)

// auditSet holds the configured overrides (0: automatic).
var auditSet struct{ memoryMB, workers int }

// SetAuditLimits sets the memory (MB) and the number of files scanned at once
// for app_code_audit (config: [tools] audit_max_memory_mb, audit_workers); 0
// keeps the automatic value. A limit of the service's cgroup (systemd
// MemoryMax=, CPUQuota=) still applies.
func SetAuditLimits(memoryMB, workers int) {
	auditSet.memoryMB, auditSet.workers = max(memoryMB, 0), max(workers, 0)
}

// currentBudget works out the budget from the machine as it is now:
//
//   - heap: min(1 GiB, 25% of the available memory, 50% of the cgroup's
//     memory limit); a configured value replaces the first two, never the
//     cgroup's;
//   - workers: min(4, max(1, CPUs/2)), where CPUs counts a cgroup CPU quota;
//     a configured value replaces it, up to the CPUs; 1 while the load
//     average is above the CPUs;
//   - the Go memory limit: the heap budget itself, so that the process stays
//     within it (calls across files let caches go well before, see
//     engine.ProjectOptions.MaxHeap), and at most 75% of the cgroup's limit.
func currentBudget() auditBudget {
	res := hostResources()
	heap := uint64(1 << 30)
	if avail := res.MemAvailableBytes; avail > 0 {
		heap = min(heap, avail/4)
	}
	if auditSet.memoryMB > 0 {
		heap = uint64(auditSet.memoryMB) << 20
	}
	if cg := res.CgroupMemoryLimit; cg > 0 {
		heap = min(heap, cg/2)
	}
	heap = max(heap, 16<<20)
	limit := heap

	cpus := min(runtime.NumCPU(), runtime.GOMAXPROCS(0))
	if q := res.CgroupCPUs; q > 0 {
		cpus = min(cpus, q)
	}
	cpus = max(cpus, 1)
	workers := min(4, max(1, cpus/2))
	if auditSet.workers > 0 {
		workers = min(auditSet.workers, cpus)
	}
	if res.Load1 > float64(cpus) {
		workers = 1
	}
	return auditBudget{heap: heap, limit: limit, workers: workers}
}

// projectTokens scales the parsed-file cache with the heap: 3M tokens at 1 GiB.
func (b auditBudget) projectTokens() int {
	return max(int(uint64(3_000_000)*b.heap/(1<<30)), 100_000)
}

// hostResources reads the resources fact through hostenv, with procDir and
// cgroupDir remapped when tests point them elsewhere.
func hostResources() hostenv.Resources {
	src, err := hostenv.NewLive(nil)
	if err != nil {
		return hostenv.Resources{}
	}
	src.Remap = map[string]string{"/proc": procDir, hostenv.CgroupRoot: cgroupDir}
	return hostenv.LinuxCollector{}.Resources(src).Value
}
