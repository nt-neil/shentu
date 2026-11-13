package hostenv

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bigProcNet writes a /proc/net/tcp of n rows (about 180 bytes each, as on
// a busy server) whose last row is a public mysqld listener and an SSH
// peer just before it.
func bigProcNet(t testing.TB, n int) string {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "net"), 0o755)
	var b strings.Builder
	b.WriteString("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	row := func(i int, local, remote, st string, inode int) {
		fmt.Fprintf(&b, "%6d: %s %s %s 00000000:00000000 00:00000000 00000000   33        0 %d 1 0000000000000000 20 4 30 10 -1                                                 \n",
			i, local, remote, st, inode)
	}
	for i := 0; i < n-2; i++ {
		row(i, "0100007F:0050", fmt.Sprintf("0100007F:%04X", 1024+i%60000), "01", 100000+i)
	}
	row(n-2, "0F02000A:0016", "0900710C:D431", "01", 9) // 10.0.2.15:22 <- 12.113.0.9
	row(n-1, "00000000:0CEA", "00000000:0000", "0A", 7) // 0.0.0.0:3306 LISTEN
	os.WriteFile(filepath.Join(dir, "net", "tcp"), []byte(b.String()), 0o644)
	return dir
}

// B2: a 9 MiB table (52430 rows) is read whole: the last row still counts.
func TestProcNetLarge(t *testing.T) {
	dir := bigProcNet(t, 52430)
	st, _ := os.Stat(filepath.Join(dir, "net", "tcp"))
	if st.Size() < 9<<20 {
		t.Fatalf("table is %d bytes, want over 9 MiB", st.Size())
	}
	live := &Live{Remap: map[string]string{"/proc": dir}}
	got := LinuxCollector{}.Listeners(live, map[string]int{"7": 42})
	found := false
	for _, l := range got.Value {
		found = found || l.Port == 3306 && l.Addr == "0.0.0.0" && l.PID == 42
	}
	if !found || got.Status == StatusUnknown {
		t.Errorf("mysqld at the end of a 9 MiB table missing: %+v", got)
	}
	rows := 0
	if err := ScanProcNet(live, "tcp", func(ProcNetEntry) { rows++ }); err != nil || rows != 52430 {
		t.Errorf("rows %d, err %v", rows, err)
	}
	// Only a single line is limited.
	os.WriteFile(filepath.Join(dir, "net", "tcp6"), []byte("hdr\n"+strings.Repeat("x", MaxLineBytes+1)+"\n"), 0o644)
	if got := (LinuxCollector{}).Listeners(live, nil); got.Status != StatusPartial {
		t.Errorf("an over-long line: %s %s", got.Status, got.Detail)
	}
}
