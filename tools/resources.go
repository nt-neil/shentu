package tools

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Shentu runs on the customer's production server, so app_code_audit sizes
// itself to the machine: on a small VPS it must not slow the sites down or
// get the process killed for memory.

// auditBudget is what one audit may use.
type auditBudget struct {
	heap    uint64 // heap in use past which calls stop crossing files
	limit   uint64 // Go's soft memory limit while the audit runs (the GC works harder near it)
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
//   - the Go memory limit: twice the heap (what the GC may need on top of
//     the objects in use), and at most 75% of the cgroup's limit.
func currentBudget() auditBudget {
	heap := uint64(1 << 30)
	if avail := memAvailable(); avail > 0 {
		heap = min(heap, avail/4)
	}
	if auditSet.memoryMB > 0 {
		heap = uint64(auditSet.memoryMB) << 20
	}
	limit := 2 * heap
	if cg := cgroupMemory(); cg > 0 {
		heap = min(heap, cg/2)
		limit = min(2*heap, cg/4*3)
	}
	heap = max(heap, 16<<20)

	cpus := min(runtime.NumCPU(), runtime.GOMAXPROCS(0))
	if q := cgroupCPUs(); q > 0 {
		cpus = min(cpus, q)
	}
	cpus = max(cpus, 1)
	workers := min(4, max(1, cpus/2))
	if auditSet.workers > 0 {
		workers = min(auditSet.workers, cpus)
	}
	if loadAverage() > float64(cpus) {
		workers = 1
	}
	return auditBudget{heap: heap, limit: limit, workers: workers}
}

// projectTokens scales the parsed-file cache with the heap: 3M tokens at 1 GiB.
func (b auditBudget) projectTokens() int {
	return max(int(uint64(3_000_000)*b.heap/(1<<30)), 100_000)
}

// memAvailable is MemAvailable from /proc/meminfo, in bytes (0 if unknown).
func memAvailable() uint64 {
	f, err := os.Open(filepath.Join(procDir, "meminfo"))
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "MemAvailable:"); ok {
			kb, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
			if err == nil {
				return kb << 10
			}
		}
	}
	return 0
}

// loadAverage is the 1-minute load average (0 if unknown).
func loadAverage() float64 {
	b, err := os.ReadFile(filepath.Join(procDir, "loadavg"))
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0
	}
	l, _ := strconv.ParseFloat(fields[0], 64)
	return l
}

// cgroupDirs lists the cgroup directories that hold this process, the
// innermost first, up to the root: for cgroup v2 under cgroupDir, for v1
// under cgroupDir/<controller>. A limit anywhere on the way up applies.
func cgroupDirs(controller string) []string {
	b, err := os.ReadFile(filepath.Join(procDir, "self", "cgroup"))
	if err != nil {
		return nil
	}
	var dirs []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		base := ""
		switch {
		case parts[0] == "0" && parts[1] == "": // v2
			base = cgroupDir
		case controller != "" && strings.Contains(","+parts[1]+",", ","+controller+","): // v1
			base = filepath.Join(cgroupDir, parts[1])
		default:
			continue
		}
		p := filepath.Clean("/" + parts[2])
		for {
			dirs = append(dirs, filepath.Join(base, p))
			if p == "/" {
				break
			}
			p = filepath.Dir(p)
		}
	}
	return dirs
}

// cgroupMemory is the lowest memory limit of the process's cgroups, in bytes (0: none).
func cgroupMemory() uint64 {
	var lim uint64
	take := func(v uint64) {
		if v > 0 && v < 1<<60 && (lim == 0 || v < lim) { // v1 writes "no limit" as a huge number
			lim = v
		}
	}
	for _, d := range cgroupDirs("memory") {
		for _, name := range []string{"memory.max", "memory.limit_in_bytes"} {
			if b, err := os.ReadFile(filepath.Join(d, name)); err == nil {
				if v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); err == nil { // "max" is no limit
					take(v)
				}
			}
		}
	}
	return lim
}

// cgroupCPUs is the CPU quota of the process's cgroups, rounded up (0: none).
func cgroupCPUs() int {
	cpus := 0
	take := func(quota, period int64) {
		if quota > 0 && period > 0 {
			if n := int((quota + period - 1) / period); cpus == 0 || n < cpus {
				cpus = n
			}
		}
	}
	for _, d := range cgroupDirs("cpu") {
		if b, err := os.ReadFile(filepath.Join(d, "cpu.max")); err == nil { // v2: "quota period" or "max period"
			if f := strings.Fields(string(b)); len(f) == 2 {
				q, _ := strconv.ParseInt(f[0], 10, 64)
				p, _ := strconv.ParseInt(f[1], 10, 64)
				take(q, p)
			}
		}
		q, err1 := os.ReadFile(filepath.Join(d, "cpu.cfs_quota_us")) // v1; -1 is no quota
		p, err2 := os.ReadFile(filepath.Join(d, "cpu.cfs_period_us"))
		if err1 == nil && err2 == nil {
			qv, _ := strconv.ParseInt(strings.TrimSpace(string(q)), 10, 64)
			pv, _ := strconv.ParseInt(strings.TrimSpace(string(p)), 10, 64)
			take(qv, pv)
		}
	}
	return cpus
}
