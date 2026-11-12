package hostenv

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// writeAuthLog writes about size bytes of sshd lines: a botnet of many
// distinct sources, a few busy ones, and one that logs in.
func writeAuthLog(t *testing.T, w io.Writer, size int64, now time.Time) {
	bw := bufio.NewWriterSize(w, 1<<20)
	ts := now.Add(-time.Hour).UTC().Format("2006-01-02T15:04:05.000000-07:00")
	var n int64
	for i := 0; n < size; i++ {
		var l string
		switch {
		case i%97 == 0:
			l = fmt.Sprintf("%s vm sshd[%d]: Failed password for root from 203.0.113.%d port 4000 ssh2\n", ts, i, i%5)
		case i%100003 == 0:
			l = fmt.Sprintf("%s vm sshd[%d]: Accepted publickey for ops from 192.0.2.10 port 5000 ssh2: ED25519 SHA256:x\n", ts, i)
		default:
			l = fmt.Sprintf("%s vm sshd[%d]: Invalid user u%d from 10.%d.%d.%d port 22 [preauth]\n", ts, i, i%50000, i/65536%256, i/256%256, i%256)
		}
		k, err := bw.WriteString(l)
		if err != nil {
			t.Fatal(err)
		}
		n += int64(k)
	}
	if err := bw.Flush(); err != nil {
		t.Fatal(err)
	}
}

// peakHeap runs fn and returns the highest heap in use above where it
// started, sampled every 10 ms (each sample stops the world briefly).
func peakHeap(fn func()) uint64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	base := ms.HeapAlloc
	var peak atomic.Uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > base && m.HeapAlloc-base > peak.Load() {
				peak.Store(m.HeapAlloc - base)
			}
		}
	}()
	fn()
	close(stop)
	wg.Wait()
	return peak.Load()
}

// A 512 MB VPS must survive a 200 MB auth.log: memory may depend on the
// tracked sources and names, never on the size of the log.
func TestAuthLogStreamsInFlatMemory(t *testing.T) {
	if os.Getenv("SHENTU_HEAVY_TESTS") == "" {
		t.Skip("writes about 350 MB and parses 3M lines; set SHENTU_HEAVY_TESTS=1 (run alone, on an idle machine)")
	}
	const size = 200 << 20
	const limit = 48 << 20
	dir := t.TempDir()
	now := time.Now()
	plain := filepath.Join(dir, "auth.log")
	f, err := os.Create(plain)
	if err != nil {
		t.Fatal(err)
	}
	writeAuthLog(t, f, size, now)
	f.Close()
	gzPath := filepath.Join(dir, "secure.1.gz")
	g, _ := os.Create(gzPath)
	zw := gzip.NewWriter(g)
	writeAuthLog(t, zw, 100<<20, now)
	zw.Close()
	g.Close()

	cmdPath := filepath.Join(dir, "journal.txt")
	j, _ := os.Create(cmdPath)
	writeAuthLog(t, j, 50<<20, now)
	j.Close()
	cat := []string{"/bin/cat", cmdPath}
	registerBig(cat, 0, 15*time.Minute) // as journalctl is: a stream may outlast MaxTimeout
	t.Cleanup(func() { delete(bigCommands, argvKey(cat)) })
	live, err := NewLive([][]string{cat})
	if err != nil {
		t.Fatal(err)
	}
	live.Runner.Timeout = MaxTimeout
	since := now.Add(-48 * time.Hour)
	for _, c := range []struct {
		name string
		run  func(add func(string)) error
	}{
		{"auth.log 200 MB", func(add func(string)) error {
			_, err := LinuxCollector{}.ScanAuthLogs(context.Background(), live, []string{plain}, since, add)
			return err
		}},
		{"secure.1.gz 100 MB unpacked", func(add func(string)) error { return ScanLines(live, gzPath, add) }},
		{"command output 50 MB", func(add func(string)) error {
			if _, err := os.Stat("/bin/cat"); err != nil {
				t.Skip("no /bin/cat")
			}
			_, err := RunLines(context.Background(), live, cat, add)
			return err
		}},
	} {
		var agg *SSHLogins
		var err error
		peak := peakHeap(func() {
			agg = NewSSHLogins(since, now, "")
			err = c.run(agg.Add)
		})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		res := agg.Result()
		t.Logf("%s: peak heap %.1f MB, %d sources kept, %d evicted", c.name, float64(peak)/(1<<20), len(res), agg.Evicted())
		if peak > limit {
			t.Errorf("%s: peak heap %.1f MB, want under %d MB", c.name, float64(peak)/(1<<20), limit>>20)
		}
		if len(res) != 50 || res[0].IP[:10] != "203.0.113." || agg.Evicted() == 0 {
			t.Errorf("%s: top sources %v, evicted %d", c.name, res[:3], agg.Evicted())
		}
		ops := false
		for _, s := range agg.Result() {
			ops = ops || s.IP == "192.0.2.10"
		}
		_ = ops
	}
}
