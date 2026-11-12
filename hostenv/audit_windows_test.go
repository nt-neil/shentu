//go:build windows

package hostenv

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// TestCollectLeavesHostUnchanged runs a full live collection between two
// snapshots of what an accidental write would most likely touch: the
// firewall service's registry tree, Defender's settings and the WMI event
// subscription namespaces. The snapshots read raw registry bytes, not
// the masked values the collector sees, so a changed binary value counts.
func TestCollectLeavesHostUnchanged(t *testing.T) {
	live, err := NewLive(ForOS("windows").Allowlist())
	if err != nil {
		t.Fatal(err)
	}
	before := hostSnapshot(t, live)
	Collect(context.Background(), live)
	after := hostSnapshot(t, live)

	var diffs []string
	for k, v := range before {
		if w, ok := after[k]; !ok {
			diffs = append(diffs, "gone:    "+k)
		} else if w != v {
			diffs = append(diffs, "changed: "+k)
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			diffs = append(diffs, "new:     "+k)
		}
	}
	sort.Strings(diffs)
	if len(diffs) > 0 {
		t.Errorf("collection changed the host:\n%s", strings.Join(diffs, "\n"))
	}
	t.Logf("%d snapshot entries compared", len(before))
}

// snapshotVolatile names subkeys whose values change on their own
// (Defender stamps signature checks there), so they cannot show a write.
var snapshotVolatile = map[string]bool{"Signature Updates": true}

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
