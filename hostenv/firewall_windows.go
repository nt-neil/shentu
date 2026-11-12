//go:build windows

package hostenv

import (
	"fmt"
	"io/fs"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

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
