//go:build windows

package hostenv

// Every COM call hostenv makes lives in this file. READ-ONLY: nothing
// here may change the host. Adding a call means adding its IDL reference
// to the table below and to TestVtableSlotsMatchSDK, which checks each
// hand-counted slot against the Windows SDK headers on the CI runners.
//
//	interface             slot  method            SDK header
//	IUnknown                 2  Release           unknwn.h
//	IDispatch                5  GetIDsOfNames     oaidl.h
//	IDispatch                6  Invoke            oaidl.h
//	IWbemLocator             3  ConnectServer     wbemcli.h
//	IWbemServices           20  ExecQuery         wbemcli.h
//	IEnumWbemClassObject     4  Next              wbemcli.h
//	IWbemClassObject         4  Get               wbemcli.h
//
// INetFwPolicy2 is read by property name through IDispatch with
// DISPATCH_PROPERTYGET, never by its own slots: its getters sit between
// setters and RestoreLocalFirewallDefaults, and a property-get invoke
// cannot reach either.
//
// A minimal WMI client over raw COM: IWbemLocator.ConnectServer,
// IWbemServices.ExecQuery, IEnumWbemClassObject.Next and
// IWbemClassObject.Get, plus VARIANT / SAFEARRAY decoding. It exists for
// the two things only WMI can tell: WMI event subscriptions (persistence)
// and Defender's runtime status (MSFT_MpComputerStatus). No third-party
// COM library, no PowerShell.

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"runtime"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modole32    = windows.NewLazySystemDLL("ole32.dll")
	modoleaut32 = windows.NewLazySystemDLL("oleaut32.dll")

	procCoCreateInstance     = modole32.NewProc("CoCreateInstance")
	procCoInitializeSecurity = modole32.NewProc("CoInitializeSecurity")
	procCoSetProxyBlanket    = modole32.NewProc("CoSetProxyBlanket")

	procSysAllocString        = modoleaut32.NewProc("SysAllocString")
	procSysFreeString         = modoleaut32.NewProc("SysFreeString")
	procSysStringLen          = modoleaut32.NewProc("SysStringLen")
	procVariantClear          = modoleaut32.NewProc("VariantClear")
	procSafeArrayGetDim       = modoleaut32.NewProc("SafeArrayGetDim")
	procSafeArrayGetLBound    = modoleaut32.NewProc("SafeArrayGetLBound")
	procSafeArrayGetUBound    = modoleaut32.NewProc("SafeArrayGetUBound")
	procSafeArrayGetElemsize  = modoleaut32.NewProc("SafeArrayGetElemsize")
	procSafeArrayAccessData   = modoleaut32.NewProc("SafeArrayAccessData")
	procSafeArrayUnaccessData = modoleaut32.NewProc("SafeArrayUnaccessData")
)

var (
	clsidWbemLocator = windows.GUID{Data1: 0x4590F811, Data2: 0x1D3A, Data3: 0x11D0, Data4: [8]byte{0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}}
	iidIWbemLocator  = windows.GUID{Data1: 0xDC12A687, Data2: 0x737F, Data3: 0x11CF, Data4: [8]byte{0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}}
)

const (
	clsctxInprocServer      = 0x1
	rpcCAuthnLevelDefault   = 0
	rpcCAuthnLevelCall      = 3
	rpcCImpLevelImpersonate = 3
	rpcCAuthnWinNT          = 10
	rpcCAuthzNone           = 0
	eoacNone                = 0
	wbemFlagForwardOnly     = 0x20
	wbemFlagReturnImmediate = 0x10
	wbemSTimedOut           = 0x40004
	wmiNextTimeoutMS        = 10000
	hrRPCETooLate           = 0x80010119
	hrSFalse                = 1
	hrRPCEChangedMode       = 0x80010106
	wbemEAccessDenied       = 0x80041003
	wbemEInvalidNamespace   = 0x8004100E
	wbemEInvalidClass       = 0x80041010
	wbemENotFound           = 0x80041002
	wbemEInvalidQuery       = 0x80041017
	eAccessDenied           = 0x80070005
	ePointer                = 0x80004003
	maxWMIRows              = 10000
	maxVariantArray         = 10000
	maxVariantString        = 64 << 10
)

// Vtable slots (wbemcli.h). IUnknown is 0-2 everywhere.
const (
	vtRelease              = 2
	vtLocatorConnectServer = 3
	vtServicesExecQuery    = 20
	vtEnumNext             = 4
	vtObjectGet            = 4
)

// VARIANT types.
const (
	vtEmpty   = 0
	vtNull    = 1
	vtI2      = 2
	vtI4      = 3
	vtR4      = 4
	vtR8      = 5
	vtDate    = 7
	vtBSTR    = 8
	vtBool    = 11
	vtI1      = 16
	vtUI1     = 17
	vtUI2     = 18
	vtUI4     = 19
	vtI8      = 20
	vtUI8     = 21
	vtInt     = 22
	vtUInt    = 23
	vtArray   = 0x2000
	vtByRef   = 0x4000
	vtTypeMsk = 0x0FFF
)

// variant is a VARIANT: 24 bytes on 64-bit Windows, 16 on 32-bit. The
// value union starts at offset 8 on both.
type variant struct {
	VT  uint16
	_   [3]uint16
	Val uint64
	_   uintptr // the second word of BRECORD on 64-bit
}

// hresultErr maps WMI and COM failures to the fs errors Classify knows.
type hresultErr struct {
	op string
	hr uint32
}

func (e *hresultErr) Error() string { return fmt.Sprintf("%s: HRESULT 0x%08X", e.op, e.hr) }

func (e *hresultErr) Is(target error) bool {
	switch target {
	case fs.ErrPermission:
		return e.hr == wbemEAccessDenied || e.hr == eAccessDenied
	case fs.ErrNotExist:
		return e.hr == wbemEInvalidNamespace || e.hr == wbemEInvalidClass || e.hr == wbemENotFound
	case ErrTimeout:
		return e.hr == wbemSTimedOut
	}
	return false
}

func hr(op string, r uintptr) error {
	if int32(r) >= 0 && uint32(r) != wbemSTimedOut {
		return nil
	}
	return &hresultErr{op: op, hr: uint32(r)}
}

// call invokes vtable slot i of the COM object obj. A nil object (a call
// that reported success without an out-pointer) is E_POINTER, never a
// dereference.
//
// Callers pass out-pointers as uintptr(unsafe.Pointer(&x)). Without
// uintptrescapes x could stay on the goroutine's stack, the stack could
// grow and move inside call (the append below), and COM would write to
// the old copy: an "S_OK with a nil enumerator" (seen once on CI). With
// it, as for syscall.SyscallN, such x live on the heap for the call.
//
//go:uintptrescapes
func call(obj unsafe.Pointer, i int, args ...uintptr) uintptr {
	if obj == nil {
		return ePointer
	}
	vtbl := *(*unsafe.Pointer)(obj)
	fn := *(*uintptr)(unsafe.Add(vtbl, uintptr(i)*unsafe.Sizeof(uintptr(0))))
	r, _, _ := syscall.SyscallN(fn, append([]uintptr{uintptr(obj)}, args...)...)
	return r
}

func release(obj unsafe.Pointer) {
	if obj != nil {
		call(obj, vtRelease)
	}
}

func bstr(s string) (uintptr, error) {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return 0, err
	}
	b, _, _ := procSysAllocString.Call(uintptr(unsafe.Pointer(p)))
	if b == 0 {
		return 0, errors.New("hostenv: SysAllocString failed")
	}
	return b, nil
}

func freeBSTR(b uintptr) {
	if b != 0 {
		procSysFreeString.Call(b)
	}
}

// bstrString reads a BSTR by its length prefix (it may hold NULs), capped.
func bstrString(b unsafe.Pointer) string {
	if b == nil {
		return ""
	}
	n, _, _ := procSysStringLen.Call(uintptr(b))
	if n > maxVariantString {
		n = maxVariantString
	}
	return string(utf16.Decode(unsafe.Slice((*uint16)(b), n))) // keeps embedded NULs
}

// WMI runs one WQL query and returns props of each row. COM needs a
// thread of its own, initialised for the multithreaded apartment.
func (l *Live) WMI(namespace, query string, props []string) ([]map[string]any, error) {
	type result struct {
		rows []map[string]any
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		rows, err := execWQL(namespace, query, props)
		ch <- result{rows, err}
	}()
	r := <-ch
	if r.err != nil {
		return r.rows, &fs.PathError{Op: "WMI", Path: namespace + ": " + query, Err: r.err}
	}
	return r.rows, nil
}

// comInit loads the COM DLLs and joins the multithreaded apartment on
// the calling (locked) OS thread. Call windows.CoUninitialize after a
// nil error.
func comInit() error {
	if err := modole32.Load(); err != nil {
		return err
	}
	if err := modoleaut32.Load(); err != nil {
		return err
	}
	if err := windows.CoInitializeEx(0, windows.COINIT_MULTITHREADED); err != nil {
		var errno syscall.Errno
		if !errors.As(err, &errno) || (uint32(errno) != hrSFalse && uint32(errno) != hrRPCEChangedMode) {
			return err
		}
	}
	return nil
}

func execWQL(namespace, query string, props []string) ([]map[string]any, error) {
	if err := comInit(); err != nil {
		return nil, err
	}
	defer windows.CoUninitialize()
	// Process-wide security; another caller may have set it already.
	if r, _, _ := procCoInitializeSecurity.Call(0, math.MaxUint32, 0, 0, rpcCAuthnLevelDefault, rpcCImpLevelImpersonate, 0, eoacNone, 0); int32(r) < 0 && uint32(r) != hrRPCETooLate {
		return nil, hr("CoInitializeSecurity", r)
	}
	var locator unsafe.Pointer
	r, _, _ := procCoCreateInstance.Call(uintptr(unsafe.Pointer(&clsidWbemLocator)), 0, clsctxInprocServer,
		uintptr(unsafe.Pointer(&iidIWbemLocator)), uintptr(unsafe.Pointer(&locator)))
	if err := hr("CoCreateInstance(WbemLocator)", r); err != nil {
		return nil, err
	}
	defer release(locator)

	ns, err := bstr(namespace)
	if err != nil {
		return nil, err
	}
	defer freeBSTR(ns)
	var services unsafe.Pointer
	if err := hr("ConnectServer", call(locator, vtLocatorConnectServer, ns, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&services)))); err != nil {
		return nil, err
	}
	defer release(services)
	r, _, _ = procCoSetProxyBlanket.Call(uintptr(services), rpcCAuthnWinNT, rpcCAuthzNone, 0, rpcCAuthnLevelCall, rpcCImpLevelImpersonate, 0, eoacNone)
	if err := hr("CoSetProxyBlanket", r); err != nil {
		return nil, err
	}

	lang, err := bstr("WQL")
	if err != nil {
		return nil, err
	}
	defer freeBSTR(lang)
	q, err := bstr(query)
	if err != nil {
		return nil, err
	}
	defer freeBSTR(q)
	var enum unsafe.Pointer
	r = call(services, vtServicesExecQuery, lang, q, wbemFlagForwardOnly|wbemFlagReturnImmediate, 0, uintptr(unsafe.Pointer(&enum)))
	if err := hr("ExecQuery", r); err != nil {
		return nil, err
	}
	if enum == nil { // seen once on windows-2025 CI: success, no enumerator
		return nil, &hresultErr{op: "ExecQuery returned no enumerator", hr: uint32(r)}
	}
	defer release(enum)

	names := make([]*uint16, len(props))
	for i, p := range props {
		if names[i], err = windows.UTF16PtrFromString(p); err != nil {
			return nil, err
		}
	}
	var rows []map[string]any
	for len(rows) < maxWMIRows {
		var obj unsafe.Pointer
		var got uint32
		r := call(enum, vtEnumNext, wmiNextTimeoutMS, 1, uintptr(unsafe.Pointer(&obj)), uintptr(unsafe.Pointer(&got)))
		if uint32(r) == wbemSTimedOut {
			return rows, &hresultErr{op: "IEnumWbemClassObject.Next", hr: wbemSTimedOut}
		}
		if err := hr("IEnumWbemClassObject.Next", r); err != nil {
			return rows, err
		}
		if got == 0 {
			break
		}
		row := make(map[string]any, len(props))
		for i, p := range props {
			var v variant
			if call(obj, vtObjectGet, uintptr(unsafe.Pointer(names[i])), 0, uintptr(unsafe.Pointer(&v)), 0, 0) == 0 {
				if val, err := decodeVariant(&v); err == nil {
					row[p] = val
				}
				procVariantClear.Call(uintptr(unsafe.Pointer(&v)))
			}
		}
		release(obj)
		rows = append(rows, row)
	}
	if len(rows) >= maxWMIRows {
		return rows, ErrTruncated
	}
	return rows, nil
}

var errVariantType = errors.New("hostenv: unsupported VARIANT type")

// decodeVariant turns a VARIANT into string, bool, int64, uint64, float64,
// nil, or a slice of those for a one-dimensional SAFEARRAY. WMI hands
// 64-bit integers over as BSTRs; they stay strings here.
func decodeVariant(v *variant) (any, error) {
	if v.VT&vtByRef != 0 {
		return nil, errVariantType
	}
	if v.VT&vtArray != 0 {
		return decodeSafeArray(uintptr(v.Val), v.VT&vtTypeMsk)
	}
	return decodeScalar(v.VT, unsafe.Pointer(&v.Val))
}

// decodeScalar reads one value of type vt stored at p.
func decodeScalar(vt uint16, p unsafe.Pointer) (any, error) {
	switch vt {
	case vtEmpty, vtNull:
		return nil, nil
	case vtBSTR:
		return bstrString(*(*unsafe.Pointer)(p)), nil
	case vtBool:
		return *(*int16)(p) != 0, nil
	case vtI1:
		return int64(*(*int8)(p)), nil
	case vtUI1:
		return int64(*(*uint8)(p)), nil
	case vtI2:
		return int64(*(*int16)(p)), nil
	case vtUI2:
		return int64(*(*uint16)(p)), nil
	case vtI4, vtInt:
		return int64(*(*int32)(p)), nil
	case vtUI4, vtUInt:
		return int64(*(*uint32)(p)), nil
	case vtI8:
		return *(*int64)(p), nil
	case vtUI8:
		return *(*uint64)(p), nil
	case vtR4:
		return float64(*(*float32)(p)), nil
	case vtR8, vtDate:
		return *(*float64)(p), nil
	}
	return nil, errVariantType
}

var scalarSize = map[uint16]uintptr{vtBSTR: unsafe.Sizeof(uintptr(0)), vtBool: 2, vtI1: 1, vtUI1: 1, vtI2: 2, vtUI2: 2,
	vtI4: 4, vtInt: 4, vtUI4: 4, vtUInt: 4, vtI8: 8, vtUI8: 8, vtR4: 4, vtR8: 8, vtDate: 8}

// decodeSafeArray reads a one-dimensional SAFEARRAY of scalars. Bounds and
// the element size come from the array itself and are checked against the
// element type before any element is touched.
func decodeSafeArray(sa uintptr, vt uint16) (any, error) {
	if sa == 0 {
		return []any{}, nil
	}
	want, ok := scalarSize[vt]
	if !ok {
		return nil, errVariantType
	}
	if dim, _, _ := procSafeArrayGetDim.Call(sa); dim != 1 {
		return nil, fmt.Errorf("hostenv: SAFEARRAY with %d dimensions", dim)
	}
	if size, _, _ := procSafeArrayGetElemsize.Call(sa); size != want {
		return nil, fmt.Errorf("hostenv: SAFEARRAY element size %d, want %d", size, want)
	}
	var lo, hi int32
	if err := hr("SafeArrayGetLBound", must3(procSafeArrayGetLBound.Call(sa, 1, uintptr(unsafe.Pointer(&lo))))); err != nil {
		return nil, err
	}
	if err := hr("SafeArrayGetUBound", must3(procSafeArrayGetUBound.Call(sa, 1, uintptr(unsafe.Pointer(&hi))))); err != nil {
		return nil, err
	}
	n := int64(hi) - int64(lo) + 1
	if n <= 0 {
		return []any{}, nil
	}
	if n > maxVariantArray {
		n = maxVariantArray
	}
	var data unsafe.Pointer
	if err := hr("SafeArrayAccessData", must3(procSafeArrayAccessData.Call(sa, uintptr(unsafe.Pointer(&data))))); err != nil {
		return nil, err
	}
	defer procSafeArrayUnaccessData.Call(sa)
	out := make([]any, 0, n)
	for i := int64(0); i < n; i++ {
		v, err := decodeScalar(vt, unsafe.Add(data, uintptr(i)*want))
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func must3(r, _ uintptr, _ error) uintptr { return r }

// ---- INetFwPolicy2 (netfw.h) ----

// INetFwPolicy2 (netfw.h), read through its IDispatch with the same COM
// helpers as the WMI client: no PowerShell, no netsh, no extra dependency.
var (
	clsidNetFwPolicy2 = windows.GUID{Data1: 0xE2B3C97F, Data2: 0x6AE1, Data3: 0x41AC, Data4: [8]byte{0x81, 0x7A, 0xF6, 0xF9, 0x21, 0x66, 0xD7, 0xDD}}
	iidIDispatch      = windows.GUID{Data1: 0x00020400, Data2: 0x0000, Data3: 0x0000, Data4: [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
)

// Properties are read through IDispatch by name with DISPATCH_PROPERTYGET,
// never through hand-counted vtable slots: INetFwPolicy2 interleaves
// getters with setters and RestoreLocalFirewallDefaults, so a slot off by
// one would change the firewall it is meant to inspect. A property-get
// invoke cannot reach a setter or a method.
const (
	vtDispGetIDsOfNames = 5
	vtDispInvoke        = 6
	dispatchPropertyGet = 2
	localeSystemDefault = 0x0800
	netFwActionAllow    = 1
)

// dispParams is DISPPARAMS.
type dispParams struct {
	args   *variant
	named  *int32
	nArgs  uint32
	nNamed uint32
}

// getProp reads property name of the IDispatch object d, passing arg
// (a NET_FW_PROFILE_TYPE2) as its index when arg is not negative.
func getProp(d unsafe.Pointer, name string, arg int32) (any, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var id int32
	var iidNull windows.GUID
	if err := hr("GetIDsOfNames("+name+")", call(d, vtDispGetIDsOfNames, uintptr(unsafe.Pointer(&iidNull)),
		uintptr(unsafe.Pointer(&n)), 1, localeSystemDefault, uintptr(unsafe.Pointer(&id)))); err != nil {
		return nil, err
	}
	var params dispParams
	in := variant{VT: vtI4, Val: uint64(uint32(arg))}
	if arg >= 0 {
		params.args, params.nArgs = &in, 1
	}
	var out variant
	if err := hr("Invoke("+name+")", call(d, vtDispInvoke, uintptr(id), uintptr(unsafe.Pointer(&iidNull)), localeSystemDefault,
		dispatchPropertyGet, uintptr(unsafe.Pointer(&params)), uintptr(unsafe.Pointer(&out)), 0, 0)); err != nil {
		return nil, err
	}
	defer procVariantClear.Call(uintptr(unsafe.Pointer(&out)))
	return decodeVariant(&out)
}

var fwProfiles = []struct {
	bit  int32 // NET_FW_PROFILE_TYPE2
	name string
}{{1, "Domain"}, {2, "Private"}, {4, "Public"}}

func (l *Live) FirewallPolicy() (WinFirewallPolicy, error) {
	type result struct {
		pol WinFirewallPolicy
		err error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		pol, err := firewallPolicy()
		ch <- result{pol, err}
	}()
	r := <-ch
	if r.err != nil {
		return r.pol, &fs.PathError{Op: "INetFwPolicy2", Path: "HNetCfg.FwPolicy2", Err: r.err}
	}
	return r.pol, nil
}

func firewallPolicy() (WinFirewallPolicy, error) {
	pol := WinFirewallPolicy{Profiles: map[string]WinFirewallProfile{}}
	if err := comInit(); err != nil {
		return pol, err
	}
	defer windows.CoUninitialize()
	var p unsafe.Pointer
	r, _, _ := procCoCreateInstance.Call(uintptr(unsafe.Pointer(&clsidNetFwPolicy2)), 0, clsctxInprocServer,
		uintptr(unsafe.Pointer(&iidIDispatch)), uintptr(unsafe.Pointer(&p)))
	if err := hr("CoCreateInstance(NetFwPolicy2)", r); err != nil {
		return pol, err
	}
	defer release(p)

	cur, err := getProp(p, "CurrentProfileTypes", -1)
	if err != nil {
		return pol, err
	}
	current, ok := cur.(int64)
	if !ok {
		return pol, fmt.Errorf("CurrentProfileTypes: unexpected %T", cur)
	}
	for _, fp := range fwProfiles {
		var vals [3]any
		for i, prop := range []string{"FirewallEnabled", "BlockAllInboundTraffic", "DefaultInboundAction"} {
			if vals[i], err = getProp(p, prop, fp.bit); err != nil {
				return pol, err
			}
		}
		enabled, ok1 := vals[0].(bool)
		blockAll, ok2 := vals[1].(bool)
		action, ok3 := vals[2].(int64)
		if !ok1 || !ok2 || !ok3 {
			return pol, fmt.Errorf("INetFwPolicy2 %s: unexpected types %T %T %T", fp.name, vals[0], vals[1], vals[2])
		}
		pol.Profiles[fp.name] = WinFirewallProfile{Enabled: enabled, BlockAllInbound: blockAll, InboundAllowed: action == netFwActionAllow}
		if current&int64(fp.bit) != 0 {
			pol.Active = append(pol.Active, fp.name)
		}
	}
	return pol, nil
}

var _ WinSource = (*Live)(nil)
