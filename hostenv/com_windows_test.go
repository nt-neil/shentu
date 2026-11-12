//go:build windows

package hostenv

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These run on the Windows CI runners only. They build real VARIANTs and
// SAFEARRAYs through oleaut32 and check decodeVariant against them, at
// the edges as well as on ordinary values.

var (
	procSafeArrayCreate       = modoleaut32.NewProc("SafeArrayCreate")
	procSafeArrayCreateVector = modoleaut32.NewProc("SafeArrayCreateVector")
	procSafeArrayPutElement   = modoleaut32.NewProc("SafeArrayPutElement")
	procSafeArrayDestroy      = modoleaut32.NewProc("SafeArrayDestroy")
)

// safeArrayBound is SAFEARRAYBOUND.
type safeArrayBound struct {
	Elements uint32
	LBound   int32
}

func newBSTR(t testing.TB, s string) uintptr {
	u := append(utf16.Encode([]rune(s)), 0) // SysAllocStringLen keeps embedded NULs
	alloc := modoleaut32.NewProc("SysAllocStringLen")
	b, _, _ := alloc.Call(uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)-1))
	if b == 0 {
		t.Fatal("SysAllocStringLen")
	}
	return b
}

// bstrArray builds a VT_ARRAY|VT_BSTR variant with the given lower bound.
// SafeArrayPutElement copies each BSTR, so ours are freed here.
func bstrArray(t testing.TB, lbound int32, items []string) (variant, func()) {
	sa, _, _ := procSafeArrayCreateVector.Call(vtBSTR, uintptr(lbound), uintptr(len(items)))
	if sa == 0 {
		t.Fatal("SafeArrayCreateVector")
	}
	for i, s := range items {
		b := newBSTR(t, s)
		idx := lbound + int32(i)
		if r, _, _ := procSafeArrayPutElement.Call(sa, uintptr(unsafe.Pointer(&idx)), b); r != 0 {
			t.Fatalf("SafeArrayPutElement: 0x%x", r)
		}
		freeBSTR(b)
	}
	return variant{VT: vtArray | vtBSTR, Val: uint64(sa)}, func() { procSafeArrayDestroy.Call(sa) }
}

func intArray(t testing.TB, vt uint16, vals []int32) (variant, func()) {
	sa, _, _ := procSafeArrayCreateVector.Call(uintptr(vt), 0, uintptr(len(vals)))
	if sa == 0 {
		t.Fatal("SafeArrayCreateVector")
	}
	for i := range vals {
		idx := int32(i)
		if r, _, _ := procSafeArrayPutElement.Call(sa, uintptr(unsafe.Pointer(&idx)), uintptr(unsafe.Pointer(&vals[i]))); r != 0 {
			t.Fatalf("SafeArrayPutElement: 0x%x", r)
		}
	}
	return variant{VT: vtArray | vt, Val: uint64(sa)}, func() { procSafeArrayDestroy.Call(sa) }
}

func TestDecodeVariantScalars(t *testing.T) {
	b := newBSTR(t, "Normal")
	defer freeBSTR(b)
	for _, c := range []struct {
		v    variant
		want any
	}{
		{variant{VT: vtEmpty}, nil},
		{variant{VT: vtNull}, nil},
		{variant{VT: vtBool, Val: 0xFFFF}, true},
		{variant{VT: vtBool, Val: 0}, false},
		{variant{VT: vtI4, Val: uint64(uint32(0xFFFFFFFF))}, int64(-1)},
		{variant{VT: vtUI4, Val: 0xFFFFFFFF}, int64(0xFFFFFFFF)},
		{variant{VT: vtUI1, Val: 0x1FF}, int64(0xFF)}, // only the low byte belongs to the value
		{variant{VT: vtI8, Val: 1 << 62}, int64(1 << 62)},
		{variant{VT: vtUI8, Val: 1<<64 - 1}, uint64(1<<64 - 1)},
		{variant{VT: vtBSTR, Val: uint64(b)}, "Normal"},
		{variant{VT: vtBSTR, Val: 0}, ""}, // NULL BSTR is the empty string
	} {
		got, err := decodeVariant(&c.v)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("vt %d: got %#v, %v; want %#v", c.v.VT, got, err, c.want)
		}
	}
	for _, vt := range []uint16{13 /* VT_UNKNOWN */, 9 /* VT_DISPATCH */, vtByRef | vtI4, 36 /* VT_RECORD */} {
		if _, err := decodeVariant(&variant{VT: vt, Val: 0xdeadbeef}); err == nil {
			t.Errorf("vt 0x%x must be refused, not dereferenced", vt)
		}
	}
}

func TestDecodeSafeArrayEdges(t *testing.T) {
	v, done := bstrArray(t, -5, []string{`C:\`, "", "a\x00b", strings.Repeat("x", maxVariantString+10)})
	defer done()
	got, err := decodeVariant(&v)
	if err != nil {
		t.Fatal(err)
	}
	g := got.([]any)
	if len(g) != 4 || g[0] != `C:\` || g[1] != "" || g[2] != "a\x00b" || len(g[3].(string)) != maxVariantString {
		t.Errorf("negative lbound, empty, embedded NUL, capped: %#v", g[:3])
	}

	v, done = bstrArray(t, 0, nil)
	defer done()
	if got, err := decodeVariant(&v); err != nil || len(got.([]any)) != 0 {
		t.Errorf("empty array: %#v %v", got, err)
	}
	if got, err := decodeVariant(&variant{VT: vtArray | vtBSTR}); err != nil || len(got.([]any)) != 0 {
		t.Errorf("NULL SAFEARRAY pointer: %#v %v", got, err)
	}

	v, done = intArray(t, vtI4, []int32{1, -2, 3})
	defer done()
	if got, err := decodeVariant(&v); err != nil || !reflect.DeepEqual(got, []any{int64(1), int64(-2), int64(3)}) {
		t.Errorf("I4 array: %#v %v", got, err)
	}
	// The variant claims 8-byte elements over a 4-byte array: refused.
	bad := variant{VT: vtArray | vtI8, Val: v.Val}
	if _, err := decodeVariant(&bad); err == nil {
		t.Error("element size mismatch must be refused")
	}
	// Two dimensions: refused.
	bounds := [2]safeArrayBound{{2, 0}, {2, 0}}
	sa2, _, _ := procSafeArrayCreate.Call(vtI4, 2, uintptr(unsafe.Pointer(&bounds[0])))
	defer procSafeArrayDestroy.Call(sa2)
	if _, err := decodeVariant(&variant{VT: vtArray | vtI4, Val: uint64(sa2)}); err == nil {
		t.Error("2-D array must be refused")
	}
	// Array of VARIANTs (VT_ARRAY|VT_VARIANT) is not a scalar array: refused.
	if _, err := decodeVariant(&variant{VT: vtArray | 12, Val: v.Val}); err == nil {
		t.Error("VT_ARRAY|VT_VARIANT must be refused")
	}
}

func FuzzDecodeBSTRArray(f *testing.F) {
	f.Add("a|b|c", int32(0))
	f.Add("", int32(-1))
	f.Add("\x00|\xff\xfe|日本語", int32(1<<20))
	f.Fuzz(func(t *testing.T, joined string, lbound int32) {
		items := strings.Split(joined, "|")
		if len(items) > 64 {
			items = items[:64]
		}
		// SafeArrayCreateVector rejects bounds that overflow; keep them sane.
		if lbound > 1<<30 || lbound < -(1<<30) {
			lbound %= 1 << 30
		}
		v, done := bstrArray(t, lbound, items)
		defer done()
		got, err := decodeVariant(&v)
		if err != nil {
			t.Fatal(err)
		}
		g := got.([]any)
		if len(g) != len(items) {
			t.Fatalf("got %d items, want %d", len(g), len(items))
		}
		for i, s := range items {
			want := string([]rune(s)) // invalid UTF-8 round-trips as U+FFFD
			if g[i] != want {
				t.Errorf("item %d: %q, want %q", i, g[i], want)
			}
		}
	})
}

func FuzzDecodeScalarVariant(f *testing.F) {
	f.Add(uint16(vtI4), uint64(7))
	f.Add(uint16(vtBool), uint64(1))
	f.Fuzz(func(t *testing.T, vt uint16, val uint64) {
		if vt&^vtTypeMsk != 0 || vt == vtBSTR || vt == vtArray {
			return // pointer-carrying types are covered with real allocations above
		}
		v := variant{VT: vt, Val: val}
		got, err := decodeVariant(&v)
		if _, known := scalarSize[vt]; !known && vt != vtEmpty && vt != vtNull && err == nil {
			t.Errorf("vt %d decoded to %#v instead of being refused", vt, got)
		}
	})
}

// The live client against the runner's own WMI.
func TestWMILive(t *testing.T) {
	l := &Live{}
	rows, err := l.WMI(`root\cimv2`, "SELECT * FROM Win32_OperatingSystem", []string{"Caption", "BuildNumber", "OSArchitecture"})
	if err != nil || len(rows) != 1 || !strings.Contains(rows[0]["Caption"].(string), "Windows") || rows[0]["BuildNumber"] == "" {
		t.Fatalf("Win32_OperatingSystem: %v %#v", err, rows)
	}
	if _, err := l.WMI(`root\subscription`, qWMIFilters.query, qWMIFilters.props); err != nil {
		t.Errorf("__EventFilter: %v", err)
	}
	if _, err := l.WMI(`root\no_such_namespace`, "SELECT * FROM X", []string{"Name"}); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing namespace must be not-exist: %v", err)
	}
}

// INetFwPolicy2 on the runner: all three profiles, at least one active,
// agreeing with the local registry policy and leaving it untouched.
func TestFirewallPolicyLive(t *testing.T) {
	l := &Live{}
	snapshot := func() map[string]map[string]RegValue {
		m := map[string]map[string]RegValue{}
		for _, k := range []string{"DomainProfile", "StandardProfile", "PublicProfile"} {
			m[k], _ = l.RegValues(KeyFirewallPolicy + `\` + k)
		}
		return m
	}
	before := snapshot()
	pol, err := l.FirewallPolicy()
	if err != nil || len(pol.Profiles) != 3 || len(pol.Active) == 0 {
		t.Fatalf("INetFwPolicy2: %v %+v", err, pol)
	}
	if after := snapshot(); !reflect.DeepEqual(before, after) {
		t.Fatalf("reading the policy changed it:\n before %+v\n after  %+v", before, after)
	}
	gpo := false
	for _, k := range []string{"DomainProfile", "PrivateProfile", "PublicProfile"} {
		if v, err := l.RegValues(KeyFirewallGPO + `\` + k); err == nil && len(v) > 0 {
			gpo = true
		}
	}
	for reg, name := range map[string]string{"DomainProfile": "Domain", "StandardProfile": "Private", "PublicProfile": "Public"} {
		v := before[reg]
		if gpo || v == nil {
			continue
		}
		if p := pol.Profiles[name]; p.Enabled != (regInt(v, "EnableFirewall", 1) == 1) || p.InboundAllowed != (regInt(v, "DefaultInboundAction", 1) == 0) {
			t.Errorf("%s: INetFwPolicy2 %+v disagrees with the registry %+v", name, p, v)
		}
	}
	for _, n := range pol.Active {
		if _, ok := pol.Profiles[n]; !ok {
			t.Errorf("active profile %q not among the profiles", n)
		}
	}
}

// TestVtableSlotsMatchSDK checks every hand-counted vtable slot in
// com_windows.go against the C vtable structs in the Windows SDK headers
// installed on the CI runners. HOSTENV_REQUIRE_SDK=1 (set in CI) turns a
// missing SDK into a failure instead of a skip.
func TestVtableSlotsMatchSDK(t *testing.T) {
	incs, _ := filepath.Glob(`C:\Program Files (x86)\Windows Kits\10\Include\*\um`)
	if len(incs) == 0 {
		if os.Getenv("HOSTENV_REQUIRE_SDK") != "" {
			t.Fatal("Windows SDK headers not found")
		}
		t.Skip("Windows SDK headers not installed")
	}
	sort.Strings(incs)
	um := incs[len(incs)-1]
	t.Logf("SDK headers: %s", um)
	method := regexp.MustCompile(`\(\s*STDMETHODCALLTYPE\s*\*\s*(\w+)\s*\)`)
	slots := func(header, iface string) []string {
		b, err := os.ReadFile(filepath.Join(um, header))
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		start := strings.Index(src, "typedef struct "+iface+"Vtbl")
		if start < 0 {
			t.Fatalf("%s: no %sVtbl", header, iface)
		}
		end := strings.Index(src[start:], "} "+iface+"Vtbl;")
		if end < 0 {
			t.Fatalf("%s: %sVtbl not closed", header, iface)
		}
		var names []string
		for _, m := range method.FindAllStringSubmatch(src[start:start+end], -1) {
			names = append(names, m[1])
		}
		return names
	}
	for _, c := range []struct {
		header, iface, method string
		slot                  int
	}{
		{"unknwn.h", "IUnknown", "Release", vtRelease},
		{"oaidl.h", "IDispatch", "GetIDsOfNames", vtDispGetIDsOfNames},
		{"oaidl.h", "IDispatch", "Invoke", vtDispInvoke},
		{"wbemcli.h", "IWbemLocator", "ConnectServer", vtLocatorConnectServer},
		{"wbemcli.h", "IWbemServices", "ExecQuery", vtServicesExecQuery},
		{"wbemcli.h", "IEnumWbemClassObject", "Next", vtEnumNext},
		{"wbemcli.h", "IWbemClassObject", "Get", vtObjectGet},
	} {
		names := slots(c.header, c.iface)
		if c.slot >= len(names) || names[c.slot] != c.method {
			t.Errorf("%s slot %d is %v in %s, want %s", c.iface, c.slot, names, c.header, c.method)
		} else {
			t.Logf("%-22s %2d %-14s %s", c.iface, c.slot, c.method, c.header)
		}
	}
}

// call must deliver an out-pointer's write to the variable even when the
// stack grows inside call. A fake COM object writes through its argument;
// calling it at many stack depths makes the growth fall inside call at
// some depth. Without //go:uintptrescapes on call this loses writes.
func TestCallOutPointerSurvivesStackGrowth(t *testing.T) {
	move := windows.NewLazySystemDLL("kernel32.dll").NewProc("RtlMoveMemory")
	method := windows.NewCallback(func(this, out uintptr) uintptr {
		v := uint64(0xC0FFEE)
		move.Call(out, uintptr(unsafe.Pointer(&v)), 8)
		return 0
	})
	vtbl := [1]uintptr{method}
	obj := struct{ vtbl *[1]uintptr }{&vtbl}
	var deep func(n int) uint64
	deep = func(n int) uint64 {
		var pad [64]byte
		pad[n%64] = byte(n)
		if n == 0 {
			var out uint64
			call(unsafe.Pointer(&obj), 0, uintptr(unsafe.Pointer(&out)))
			return out + uint64(pad[0]&0)
		}
		return deep(n-1) + uint64(pad[n%64]&0)
	}
	done := make(chan []int)
	go func() { // a fresh goroutine: a small stack that grows as it deepens
		var bad []int
		for n := 0; n < 3000; n += 7 {
			if got := deep(n); got != 0xC0FFEE {
				bad = append(bad, n)
			}
		}
		done <- bad
	}()
	if bad := <-done; len(bad) > 0 {
		t.Errorf("COM writes lost at %d stack depths (first %d)", len(bad), bad[0])
	}
}
