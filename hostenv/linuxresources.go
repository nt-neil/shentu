package hostenv

// Resources on Linux: /proc/meminfo, /proc/loadavg and the cgroup limits of
// the collecting process. Moved from tools/resources.go (Phase 1c); the
// logic is unchanged, including "0 means unknown".

import (
	"bufio"
	"path"
	"strconv"
	"strings"
)

// CgroupRoot is where the cgroup file system is mounted.
const CgroupRoot = "/sys/fs/cgroup"

// Resources gathers the resources fact on its own, for callers (the code
// audit's budget) that need nothing else.
func (LinuxCollector) Resources(src Source) Obs[Resources] {
	var r Resources
	mi, err := src.ReadFile("/proc/meminfo")
	if err == nil {
		r.MemTotalBytes, r.MemAvailableBytes = ParseMeminfo(mi)
	}
	if b, lerr := src.ReadFile("/proc/loadavg"); lerr == nil {
		r.Load1 = ParseLoadavg(b)
	}
	r.CgroupMemoryLimit = cgroupMemory(src)
	r.CgroupCPUs = cgroupCPUs(src)
	if err != nil {
		return Obs[Resources]{Status: StatusPartial, Reason: Classify(err), Detail: "/proc/meminfo: " + err.Error(), Value: r}
	}
	return OK(r)
}

// ParseMeminfo returns MemTotal and MemAvailable in bytes (0 if absent).
func ParseMeminfo(b []byte) (total, avail uint64) {
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		l := sc.Text()
		for _, k := range []string{"MemTotal:", "MemAvailable:"} {
			if v, ok := strings.CutPrefix(l, k); ok {
				kb, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
				if err != nil {
					continue
				}
				if k == "MemTotal:" {
					total = kb << 10
				} else {
					avail = kb << 10
				}
			}
		}
	}
	return total, avail
}

// ParseLoadavg is the 1-minute load average (0 if unreadable).
func ParseLoadavg(b []byte) float64 {
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	l, _ := strconv.ParseFloat(f[0], 64)
	return l
}

// CgroupDirs lists the cgroup directories that hold the process described
// by /proc/self/cgroup (b), innermost first, up to the root: for cgroup v2
// under CgroupRoot, for v1 under CgroupRoot/<controller>. A limit anywhere
// on the way up applies.
func CgroupDirs(b []byte, controller string) []string {
	var dirs []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		base := ""
		switch {
		case parts[0] == "0" && parts[1] == "": // v2
			base = CgroupRoot
		case controller != "" && strings.Contains(","+parts[1]+",", ","+controller+","): // v1
			base = path.Join(CgroupRoot, parts[1])
		default:
			continue
		}
		p := path.Clean("/" + parts[2])
		for {
			dirs = append(dirs, path.Join(base, p))
			if p == "/" {
				break
			}
			p = path.Dir(p)
		}
	}
	return dirs
}

func selfCgroupDirs(src Source, controller string) []string {
	b, err := src.ReadFile("/proc/self/cgroup")
	if err != nil {
		return nil
	}
	return CgroupDirs(b, controller)
}

// cgroupMemory is the lowest memory limit of the process's cgroups (0: none).
func cgroupMemory(src Source) uint64 {
	var lim uint64
	take := func(v uint64) {
		if v > 0 && v < 1<<60 && (lim == 0 || v < lim) { // v1 writes "no limit" as a huge number
			lim = v
		}
	}
	for _, d := range selfCgroupDirs(src, "memory") {
		for _, name := range []string{"memory.max", "memory.limit_in_bytes"} {
			if b, err := src.ReadFile(path.Join(d, name)); err == nil {
				if v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); err == nil { // "max" is no limit
					take(v)
				}
			}
		}
	}
	return lim
}

// cgroupCPUs is the CPU quota of the process's cgroups, rounded up (0: none).
func cgroupCPUs(src Source) int {
	cpus := 0
	take := func(quota, period int64) {
		if quota > 0 && period > 0 {
			if n := int((quota + period - 1) / period); cpus == 0 || n < cpus {
				cpus = n
			}
		}
	}
	for _, d := range selfCgroupDirs(src, "cpu") {
		if b, err := src.ReadFile(path.Join(d, "cpu.max")); err == nil { // v2: "quota period" or "max period"
			if f := strings.Fields(string(b)); len(f) == 2 {
				q, _ := strconv.ParseInt(f[0], 10, 64)
				p, _ := strconv.ParseInt(f[1], 10, 64)
				take(q, p)
			}
		}
		q, err1 := src.ReadFile(path.Join(d, "cpu.cfs_quota_us")) // v1; -1 is no quota
		p, err2 := src.ReadFile(path.Join(d, "cpu.cfs_period_us"))
		if err1 == nil && err2 == nil {
			qv, _ := strconv.ParseInt(strings.TrimSpace(string(q)), 10, 64)
			pv, _ := strconv.ParseInt(strings.TrimSpace(string(p)), 10, 64)
			take(qv, pv)
		}
	}
	return cpus
}
