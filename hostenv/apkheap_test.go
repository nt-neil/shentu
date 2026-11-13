package hostenv

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// N2-5: apk's database is streamed once; only the files asked about are
// kept, so a 50 MB database does not make a 50 MB heap.
func TestApkDBFlatMemory(t *testing.T) {
	if os.Getenv("SHENTU_HEAVY_TESTS") == "" {
		t.Skip("writes 50 MB; set SHENTU_HEAVY_TESTS=1 (run alone, on an idle machine)")
	}
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "lib/apk/db"), 0o755)
	f, _ := os.Create(filepath.Join(root, "lib/apk/db/installed"))
	w := bufio.NewWriter(f)
	n := 0
	for i := 0; n < 50<<20; i++ {
		k, _ := fmt.Fprintf(w, "P:pkg%d\nV:1.%d-r0\nA:aarch64\nF:usr/share/pkg%d\n", i, i, i)
		n += k
		for j := 0; j < 40; j++ {
			k, _ = fmt.Fprintf(w, "R:some-long-file-name-%d.txt\n", j)
			n += k
		}
		w.WriteString("\n")
	}
	w.WriteString("P:openrc-svc\nV:1-r0\nA:aarch64\nF:etc/init.d\nR:sshd\n\n")
	w.Flush()
	f.Close()
	live := &Live{Remap: map[string]string{"/lib": filepath.Join(root, "lib")}}
	var items []Package
	var owned map[string]bool
	var err error
	peak := peakHeap(func() { items, owned, err = ScanApkDB(live, isOpenRCScript) })
	if err != nil || !owned["/etc/init.d/sshd"] || len(owned) != 1 {
		t.Fatalf("err %v owned %v", err, owned)
	}
	t.Logf("apk db %.0f MB, %d packages: peak heap %.1f MB", float64(n)/(1<<20), len(items), float64(peak)/(1<<20))
	if peak > 24<<20 { // the package list itself, not the database
		t.Errorf("peak %d bytes", peak)
	}
}
