//go:build windows

package hostenv

import (
	"io/fs"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// INetFwPolicy2 (netfw.h), called through its vtable like the WMI client:
// no PowerShell, no netsh, no extra dependency.
var (
	clsidNetFwPolicy2 = windows.GUID{Data1: 0xE2B3C97F, Data2: 0x6AE1, Data3: 0x41AC, Data4: [8]byte{0x81, 0x7A, 0xF6, 0xF9, 0x21, 0x66, 0xD7, 0xDD}}
	iidINetFwPolicy2  = windows.GUID{Data1: 0x98325047, Data2: 0xC671, Data3: 0x4174, Data4: [8]byte{0x8D, 0x81, 0xDE, 0xFC, 0xD3, 0xF0, 0x31, 0x86}}
)

// Vtable slots: IUnknown 0-2, IDispatch 3-6, then INetFwPolicy2 in order.
const (
	vtFwCurrentProfileTypes  = 7
	vtFwFirewallEnabled      = 8
	vtFwBlockAllInbound      = 12
	vtFwDefaultInboundAction = 24
	netFwActionAllow         = 1
)

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
		uintptr(unsafe.Pointer(&iidINetFwPolicy2)), uintptr(unsafe.Pointer(&p)))
	if err := hr("CoCreateInstance(NetFwPolicy2)", r); err != nil {
		return pol, err
	}
	defer release(p)

	var current int32
	if err := hr("get_CurrentProfileTypes", call(p, vtFwCurrentProfileTypes, uintptr(unsafe.Pointer(&current)))); err != nil {
		return pol, err
	}
	for _, fp := range fwProfiles {
		var enabled, blockAll int16 // VARIANT_BOOL
		var action int32            // NET_FW_ACTION
		if err := hr("get_FirewallEnabled", call(p, vtFwFirewallEnabled, uintptr(fp.bit), uintptr(unsafe.Pointer(&enabled)))); err != nil {
			return pol, err
		}
		if err := hr("get_BlockAllInboundTraffic", call(p, vtFwBlockAllInbound, uintptr(fp.bit), uintptr(unsafe.Pointer(&blockAll)))); err != nil {
			return pol, err
		}
		if err := hr("get_DefaultInboundAction", call(p, vtFwDefaultInboundAction, uintptr(fp.bit), uintptr(unsafe.Pointer(&action)))); err != nil {
			return pol, err
		}
		pol.Profiles[fp.name] = WinFirewallProfile{Enabled: enabled != 0, BlockAllInbound: blockAll != 0, InboundAllowed: action == netFwActionAllow}
		if current&fp.bit != 0 {
			pol.Active = append(pol.Active, fp.name)
		}
	}
	return pol, nil
}

var _ WinSource = (*Live)(nil)
