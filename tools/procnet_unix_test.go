//go:build unix

package tools

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// B2: block_ip's SSH peer check reads a 9 MiB, 52430-row table in full.
func TestSSHPeersLargeTable(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "net"), 0o755)
	var b strings.Builder
	b.WriteString("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	for i := 0; i < 52429; i++ {
		fmt.Fprintf(&b, "%6d: 0100007F:0050 0100007F:%04X 01 00000000:00000000 00:00000000 00000000   33        0 %d 1 0000000000000000 20 4 30 10 -1%50s\n", i, 1024+i%60000, 100000+i, "")
	}
	b.WriteString("52429: 0F02000A:0016 0900710C:D431 01 00000000:00000000 00:00000000 00000000     0        0 9 1 0000000000000000 20 4 30 10 -1\n")
	os.WriteFile(filepath.Join(dir, "net", "tcp"), []byte(b.String()), 0o644)
	if b.Len() < 9<<20 {
		t.Fatalf("table is %d bytes", b.Len())
	}
	withHost(t, &hostenv.Live{Remap: map[string]string{"/proc": dir}})
	t.Setenv("SSH_CLIENT", "")
	peers, err := SSHPeers()
	if err != nil || !peers["12.113.0.9"] {
		t.Errorf("peers %v, err %v", peers, err)
	}
}

// N2-6: PeerUID stops at the row it looks for; the table is never held.
func TestPeerUIDStopsEarly(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "net"), 0o755)
	var b strings.Builder
	b.WriteString("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	b.WriteString("   0: 0100007F:1F90 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1001        0 9 1 0 20 4 30 10 -1\n")
	b.WriteString(strings.Repeat("x", hostenv.MaxLineBytes+1) + "\n") // never reached
	os.WriteFile(filepath.Join(dir, "net", "tcp"), []byte(b.String()), 0o644)
	withHost(t, &hostenv.Live{Remap: map[string]string{"/proc": dir}})
	uid, ok := PeerUID(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 54321}, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080})
	if !ok || uid != "1001" {
		t.Errorf("PeerUID %q %v", uid, ok)
	}
}
