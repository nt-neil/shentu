package hostenv

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// catAsQal answers rpm -qal with /bin/cat of a prepared list.
type catAsQal struct {
	*Live
	cat []string
}

func (c catAsQal) RunLinesUnmasked(ctx context.Context, argv []string, fn func(string)) (CmdResult, error) {
	return c.Live.Runner.RunLinesUnmasked(ctx, c.cat, fn)
}

// rpm -qal on a large RHEL host (300k paths, about 40 MB) must fit a 512 MB
// server: streamed, the peak is flat; the whole-output way it replaced is
// measured beside it for the record.
func TestRpmQalFlatMemory(t *testing.T) {
	if os.Getenv("SHENTU_HEAVY_TESTS") == "" {
		t.Skip("writes 40 MB and reads it twice; set SHENTU_HEAVY_TESTS=1 (run alone, on an idle machine)")
	}
	if _, err := os.Stat("/bin/cat"); err != nil {
		t.Skip("no /bin/cat")
	}
	p := filepath.Join(t.TempDir(), "qal.txt")
	f, _ := os.Create(p)
	w := bufio.NewWriter(f)
	for i := 0; i < 300000; i++ {
		fmt.Fprintf(w, "/usr/share/doc/package-%d/subdir-%d/some-long-file-name-%d.txt\n", i/40, i%40, i)
	}
	w.WriteString("/usr/lib64/security/pam_unix.so\n")
	w.Flush()
	f.Close()
	st, _ := os.Stat(p)
	cat := []string{"/bin/cat", p}
	registerBig(cat, 128<<20, MaxTimeout) // as rpm -qal is registered
	t.Cleanup(func() { delete(bigCommands, argvKey(cat)) })
	live, err := NewLive([][]string{cat})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/usr/lib64/security/pam_unix.so", "/usr/lib64/security/pam_evil.so"}
	var owned map[string]bool
	streamed := peakHeap(func() { owned, _ = RpmOwned(context.Background(), catAsQal{live, cat})(want) })
	if !owned["/usr/lib64/security/pam_unix.so"] || owned["/usr/lib64/security/pam_evil.so"] {
		t.Fatalf("owned %v", owned)
	}
	whole := peakHeap(func() { // the way before: all of stdout, masked, split, mapped
		res, _ := live.Run(context.Background(), cat)
		all := map[string]bool{}
		for _, l := range strings.Split(string(res.Stdout), "\n") {
			all[l] = true
		}
		_ = all[want[0]]
	})
	t.Logf("rpm -qal %.1f MB: peak heap streamed %.1f MB, whole output %.1f MB", float64(st.Size())/(1<<20), float64(streamed)/(1<<20), float64(whole)/(1<<20))
	if streamed > 16<<20 {
		t.Errorf("streamed peak %d bytes", streamed)
	}
}
