//go:build windows

package hostenv

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

// TestCollectLeavesHostUnchanged runs a full live collection between two
// snapshots of what an accidental write would most likely touch: the
// firewall service's registry tree, Defender's settings and the WMI event
// subscription namespaces. The snapshots read raw registry bytes, not
// the masked values the collector sees, so a changed binary value counts.
//
// Defender writes under its own key in the background, so each run also
// takes a control: the same interval with no collection, once before and
// once after. A key that changes in a control is noise and is logged, not
// failed; a key that changes only across the collection fails the test.
func TestCollectLeavesHostUnchanged(t *testing.T) {
	live, err := NewLive(ForOS("windows").Allowlist())
	if err != nil {
		t.Fatal(err)
	}
	pre := hostSnapshot(t, live)
	start := time.Now()
	before := hostSnapshot(t, live)
	gap := time.Since(start) // pre → before: a control the length of a snapshot

	start = time.Now()
	Collect(context.Background(), live)
	took := time.Since(start)
	after := hostSnapshot(t, live)
	time.Sleep(took) // after → post: a control the length of the collection
	post := hostSnapshot(t, live)

	noise := map[string]bool{}
	for _, d := range append(snapshotDiff(pre, before), snapshotDiff(after, post)...) {
		noise[d.key] = true
		t.Logf("control (no collection) saw %s %s", d.kind, d.key)
	}
	var diffs []string
	for _, d := range snapshotDiff(before, after) {
		if noise[d.key] || snapshotNoise[d.key] {
			t.Logf("ignored as noise: %s %s", d.kind, d.key)
			continue
		}
		diffs = append(diffs, d.kind+" "+d.key)
	}
	if len(diffs) > 0 {
		t.Errorf("collection changed the host:\n%s", strings.Join(diffs, "\n"))
	}
	t.Logf("%d snapshot entries compared (controls %v and %v)", len(before), gap.Round(time.Millisecond), took.Round(time.Millisecond))
}

// TestSnapshotNoise watches the snapshot with no collection at all, for
// as long as SHENTU_SNAPSHOT_WATCH says (a Go duration), and logs every
// change: CI evidence of what the host writes by itself. It never fails.
func TestSnapshotNoise(t *testing.T) {
	d, err := time.ParseDuration(os.Getenv("SHENTU_SNAPSHOT_WATCH"))
	if err != nil || d <= 0 {
		t.Skip("set SHENTU_SNAPSHOT_WATCH, such as 3m")
	}
	live, err := NewLive(ForOS("windows").Allowlist())
	if err != nil {
		t.Fatal(err)
	}
	last := hostSnapshot(t, live)
	changes := 0
	for end := time.Now().Add(d); time.Now().Before(end); {
		time.Sleep(5 * time.Second)
		cur := hostSnapshot(t, live)
		for _, c := range snapshotDiff(last, cur) {
			changes++
			t.Logf("%s no collection: %s %s", time.Now().UTC().Format(time.RFC3339), c.kind, c.key)
		}
		last = cur
	}
	t.Logf("%d changes in %v with no collection", changes, d)
}

type snapChange struct{ kind, key string }

func snapshotDiff(a, b map[string]string) []snapChange {
	var out []snapChange
	for k, v := range a {
		if w, ok := b[k]; !ok {
			out = append(out, snapChange{"gone:", k})
		} else if w != v {
			out = append(out, snapChange{"changed:", k})
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			out = append(out, snapChange{"new:", k})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

// snapshotVolatile names subkeys whose values change on their own
// (Defender stamps signature checks there), so they cannot show a write.
var snapshotVolatile = map[string]bool{"Signature Updates": true}

// snapshotNoise names single values Defender is known to write by itself,
// each with the CI run that showed it with no collection running.
var snapshotNoise = map[string]bool{
	// windows.yml run 43276183872, windows-2025: TestSnapshotNoise saw it
	// appear at 18:11:07Z with no collection running; it had failed run
	// 43274891487 (windows-2022) as "new".
	`SOFTWARE\Microsoft\Windows Defender\UX Configuration\ToastOrSsoTrigger`: true,
	// windows.yml run 43276183872, windows-2022: appeared at 18:07:07Z in
	// the watch that runs before any collection in the job.
	`SOFTWARE\Microsoft\Windows Defender\Scan\LastAggressiveCheck`: true,
}

func hostSnapshot(t *testing.T, l *Live) map[string]string {
	t.Helper()
	out := map[string]string{}
	var walk func(root registry.Key, path string, depth int)
	walk = func(root registry.Key, path string, depth int) {
		k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			out[path] = "open: " + err.Error()
			return
		}
		defer k.Close()
		names, err := k.ReadValueNames(-1)
		if err != nil {
			out[path] = "values: " + err.Error()
		}
		for _, n := range names {
			buf := make([]byte, 64<<10)
			size, typ, err := k.GetValue(n, buf)
			if err == registry.ErrShortBuffer {
				buf = make([]byte, size)
				size, typ, err = k.GetValue(n, buf)
			}
			if err != nil {
				out[path+`\`+n] = "value: " + err.Error()
				continue
			}
			out[path+`\`+n] = fmt.Sprintf("%d:%s", typ, hex.EncodeToString(buf[:min(size, len(buf))]))
		}
		if depth == 0 {
			return
		}
		subs, err := k.ReadSubKeyNames(-1)
		if err != nil {
			out[path+` [subkeys]`] = err.Error()
			return
		}
		for _, s := range subs {
			if !snapshotVolatile[s] {
				walk(root, path+`\`+s, depth-1)
			}
		}
	}
	walk(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\SharedAccess`, 8)
	walk(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows Defender`, 6)
	walk(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows Defender`, 6)

	queries := []wmiQuery{qWMIFilters, qWMICmdLine, qWMIScript, qWMIBindings,
		{"SELECT * FROM __EventConsumer", []string{"__RELPATH"}}}
	for _, ns := range []string{NamespaceSubscription, NamespaceDefaultWMI} {
		for _, q := range queries {
			rows, err := l.WMI(ns, q.query, q.props)
			b, _ := json.Marshal(rows)
			if err != nil {
				b = []byte("error: " + err.Error())
			}
			out["wmi "+ns+" "+q.query] = string(b)
		}
	}
	if len(out) < 10 {
		t.Fatalf("snapshot too small to show anything: %v", out)
	}
	return out
}
