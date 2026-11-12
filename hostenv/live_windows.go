//go:build windows

package hostenv

// Live implements WinSource on Windows with x/sys/windows and a few
// system DLL entry points x/sys does not wrap (iphlpapi, netapi32,
// wevtapi). Everything is read-only; nothing starts a process.

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
)

var (
	modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")
	modnetapi32 = windows.NewLazySystemDLL("netapi32.dll")
	modwevtapi  = windows.NewLazySystemDLL("wevtapi.dll")

	procGetExtendedTcpTable     = modiphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable     = modiphlpapi.NewProc("GetExtendedUdpTable")
	procNetLocalGroupGetMembers = modnetapi32.NewProc("NetLocalGroupGetMembers")
	procEvtQuery                = modwevtapi.NewProc("EvtQuery")
	procEvtNext                 = modwevtapi.NewProc("EvtNext")
	procEvtRender               = modwevtapi.NewProc("EvtRender")
	procEvtClose                = modwevtapi.NewProc("EvtClose")
)

// winErr wraps a Win32 error with what failed. syscall.Errno already maps
// ERROR_ACCESS_DENIED to fs.ErrPermission and ERROR_FILE_NOT_FOUND /
// ERROR_PATH_NOT_FOUND to fs.ErrNotExist; the Event Log's own "no such
// channel" codes are mapped here.
func winErr(op, what string, err error) error {
	if err == nil {
		return nil
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case 15007, 15009: // ERROR_EVT_CHANNEL_NOT_FOUND, ERROR_EVT_PUBLISHER_NOT_FOUND
			err = fmt.Errorf("%w (%v)", fs.ErrNotExist, errno)
		case 2221: // NERR_UserNotFound
			err = fmt.Errorf("%w (%v)", fs.ErrNotExist, errno)
		case 1376, 2220: // ERROR_NO_SUCH_ALIAS, NERR_GroupNotFound
			err = fmt.Errorf("%w (%v)", fs.ErrNotExist, errno)
		}
	}
	return &fs.PathError{Op: op, Path: what, Err: err}
}

// ---- registry ----

var hives = map[string]registry.Key{
	"HKLM": registry.LOCAL_MACHINE, "HKEY_LOCAL_MACHINE": registry.LOCAL_MACHINE,
	"HKU": registry.USERS, "HKEY_USERS": registry.USERS,
	"HKCU": registry.CURRENT_USER, "HKEY_CURRENT_USER": registry.CURRENT_USER,
	"HKCR": registry.CLASSES_ROOT, "HKEY_CLASSES_ROOT": registry.CLASSES_ROOT,
}

// openKey opens key read-only in the 64-bit view; WOW6432Node is read by
// spelling it out, so 32- and 64-bit builds see the same thing.
func openKey(key string, access uint32) (registry.Key, error) {
	hive, sub, _ := strings.Cut(key, `\`)
	root, ok := hives[strings.ToUpper(hive)]
	if !ok {
		return 0, &fs.PathError{Op: "RegOpenKeyEx", Path: key, Err: fs.ErrNotExist}
	}
	k, err := registry.OpenKey(root, sub, access|registry.WOW64_64KEY)
	if err != nil {
		return 0, winErr("RegOpenKeyEx", key, err)
	}
	return k, nil
}

func (l *Live) RegValues(key string) (map[string]RegValue, error) {
	k, err := openKey(key, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return nil, winErr("RegEnumValue", key, err)
	}
	out := make(map[string]RegValue, len(names))
	for _, n := range names {
		if v, ok := readValue(k, n); ok {
			out[n] = v
		}
	}
	return RedactRegValues(out), nil
}

func readValue(k registry.Key, name string) (RegValue, bool) {
	_, typ, err := k.GetValue(name, nil)
	if err != nil && !errors.Is(err, windows.ERROR_MORE_DATA) && !errors.Is(err, registry.ErrShortBuffer) {
		return RegValue{}, false
	}
	switch typ {
	case registry.SZ, registry.EXPAND_SZ:
		s, _, err := k.GetStringValue(name)
		if err != nil {
			return RegValue{}, false
		}
		t := "SZ"
		if typ == registry.EXPAND_SZ {
			t = "EXPAND_SZ"
		}
		return RegValue{Type: t, String: MaskSecrets(s)}, true
	case registry.MULTI_SZ:
		ss, _, err := k.GetStringsValue(name)
		if err != nil {
			return RegValue{}, false
		}
		for i := range ss {
			ss[i] = MaskSecrets(ss[i])
		}
		return RegValue{Type: "MULTI_SZ", Strings: ss}, true
	case registry.DWORD, registry.QWORD:
		n, _, err := k.GetIntegerValue(name)
		if err != nil {
			return RegValue{}, false
		}
		t := "DWORD"
		if typ == registry.QWORD {
			t = "QWORD"
		}
		return RegValue{Type: t, Int: n}, true
	case registry.BINARY:
		b, _, err := k.GetBinaryValue(name)
		if err != nil {
			return RegValue{}, false
		}
		if len(b) > MaxRegBinary {
			b = b[:MaxRegBinary]
		}
		return RegValue{Type: "BINARY", Bytes: b}, true
	}
	return RegValue{Type: fmt.Sprintf("TYPE_%d", typ)}, true
}

func (l *Live) RegSubkeys(key string) ([]string, error) {
	k, err := openKey(key, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, winErr("RegEnumKeyEx", key, err)
	}
	sort.Strings(names)
	return names, nil
}

// ---- services ----

var startTypes = map[uint32]string{0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled"}

var serviceStates = map[uint32]string{1: "stopped", 2: "start_pending", 3: "stop_pending", 4: "running",
	5: "continue_pending", 6: "pause_pending", 7: "paused"}

// Services opens the SCM with enumerate rights only (mgr.Connect asks for
// full access, which a standard user does not have) and each service with
// SERVICE_QUERY_CONFIG.
func (l *Live) Services() ([]WinService, error) {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, winErr("OpenSCManager", "SCM", err)
	}
	defer windows.CloseServiceHandle(h)
	var buf []byte
	var need, count, resume uint32
	var out []WinService
	for {
		var p *byte
		if len(buf) > 0 {
			p = &buf[0]
		}
		err := windows.EnumServicesStatusEx(h, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL,
			p, uint32(len(buf)), &need, &count, &resume, nil)
		if err != nil && err != windows.ERROR_MORE_DATA {
			return nil, winErr("EnumServicesStatusEx", "SCM", err)
		}
		if count > 0 {
			rows := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), count)
			for _, r := range rows {
				out = append(out, WinService{
					Name:        windows.UTF16PtrToString(r.ServiceName),
					DisplayName: windows.UTF16PtrToString(r.DisplayName),
					State:       serviceStates[r.ServiceStatusProcess.CurrentState],
					PID:         int(r.ServiceStatusProcess.ProcessId),
				})
			}
		}
		if err == nil {
			break
		}
		if need > uint32(len(buf)) {
			buf = make([]byte, need)
		} else if count == 0 {
			buf = make([]byte, 2*len(buf)+4096)
		}
	}
	for i := range out {
		serviceConfig(h, &out[i])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func serviceConfig(scm windows.Handle, s *WinService) {
	name, _ := windows.UTF16PtrFromString(s.Name)
	h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		s.ConfigErr = errCode(winErr("OpenService", s.Name, err))
		return
	}
	svc := &mgr.Service{Name: s.Name, Handle: h}
	defer svc.Close()
	c, err := svc.Config()
	if err != nil {
		s.ConfigErr = errCode(winErr("QueryServiceConfig", s.Name, err))
		return
	}
	s.BinaryPath = MaskSecrets(c.BinaryPathName)
	s.StartType = startTypes[c.StartType]
	s.Account = c.ServiceStartName
}

// ---- processes ----

func (l *Live) Processes() ([]WinProcess, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, winErr("CreateToolhelp32Snapshot", "processes", err)
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var out []WinProcess
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		p := WinProcess{PID: int(e.ProcessID), PPID: int(e.ParentProcessID), Name: windows.UTF16ToString(e.ExeFile[:])}
		processDetail(&p)
		out = append(out, p)
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return out, winErr("Process32Next", "processes", err)
	}
	return out, nil
}

func processDetail(p *WinProcess) {
	if p.PID == 0 || p.PID == 4 {
		return
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(p.PID))
	if err != nil {
		p.ExeErr = errCode(winErr("OpenProcess", p.Name, err))
		return
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		p.ExeErr = errCode(winErr("QueryFullProcessImageName", p.Name, err))
	} else {
		p.Exe = windows.UTF16ToString(buf[:n])
		if _, err := os.Lstat(p.Exe); errors.Is(err, fs.ErrNotExist) {
			p.ExeMissing = true
		}
	}
	p.Cmdline = capCmdline(processCmdline(h))
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err == nil {
		if u, err := tok.GetTokenUser(); err == nil {
			p.SID = u.User.Sid.String()
			if acct, dom, _, err := u.User.Sid.LookupAccount(""); err == nil {
				p.User = acct
				if dom != "" {
					p.User = dom + `\` + acct
				}
			}
		}
		tok.Close()
	}
}

// processCmdline asks the kernel for the command line
// (ProcessCommandLineInformation, Windows 8.1 / Server 2012 R2 and later)
// instead of reading another process's PEB.
func processCmdline(h windows.Handle) string {
	size := uint32(4096)
	for tries := 0; tries < 3; tries++ {
		buf := make([]byte, size)
		var ret uint32
		err := windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, unsafe.Pointer(&buf[0]), size, &ret)
		if err == nil {
			us := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
			return us.String()
		}
		if ret <= size {
			return ""
		}
		size = ret
	}
	return ""
}

// ---- sockets ----

const (
	afInet                 = 2
	afInet6                = 23
	tcpTableOwnerPIDListen = 3 // TCP_TABLE_OWNER_PID_LISTENER
	udpTableOwnerPID       = 1 // UDP_TABLE_OWNER_PID
	errInsufficientBuffer  = 122
	maxSocketTableAttempts = 5
)

func (l *Live) Sockets() ([]WinSocket, error) {
	var out []WinSocket
	for _, t := range []struct {
		proto string
		proc  *windows.LazyProc
		af    uintptr
		class uintptr
	}{
		{"tcp", procGetExtendedTcpTable, afInet, tcpTableOwnerPIDListen},
		{"tcp6", procGetExtendedTcpTable, afInet6, tcpTableOwnerPIDListen},
		{"udp", procGetExtendedUdpTable, afInet, udpTableOwnerPID},
		{"udp6", procGetExtendedUdpTable, afInet6, udpTableOwnerPID},
	} {
		b, err := socketTable(t.proc, t.af, t.class)
		if err != nil {
			return out, winErr(t.proc.Name, t.proto, err)
		}
		rows, err := ParseSocketTable(t.proto, b)
		if err != nil {
			return out, winErr(t.proc.Name, t.proto, err)
		}
		out = append(out, rows...)
	}
	return out, nil
}

func socketTable(proc *windows.LazyProc, af, class uintptr) ([]byte, error) {
	if err := proc.Find(); err != nil {
		return nil, err
	}
	size := uint32(16 << 10)
	for i := 0; i < maxSocketTableAttempts; i++ {
		buf := make([]byte, size)
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, af, class, 0)
		switch r {
		case 0:
			return buf[:size], nil
		case errInsufficientBuffer:
			size += 4096 // the table can grow between the two calls
			continue
		}
		return nil, syscall.Errno(r)
	}
	return nil, syscall.Errno(errInsufficientBuffer)
}

// ---- accounts ----

// userInfo1 is USER_INFO_1 (lmaccess.h).
type userInfo1 struct {
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Priv        uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}

const (
	ufAccountDisable   = 0x0002
	ufDontExpirePasswd = 0x10000
	filterNormal       = 0x0002
	maxPreferredLength = 0xFFFFFFFF
	nerrSuccess        = 0
	errorMoreData      = 234
)

func (l *Live) Users() ([]WinUser, error) {
	var out []WinUser
	var resume uint32
	for {
		var buf *byte
		var read, total uint32
		err := windows.NetUserEnum(nil, 1, filterNormal, &buf, maxPreferredLength, &read, &total, &resume)
		if err != nil && err != syscall.Errno(errorMoreData) {
			return nil, winErr("NetUserEnum", "local users", err)
		}
		if buf != nil && read > 0 {
			for _, u := range unsafe.Slice((*userInfo1)(unsafe.Pointer(buf)), read) {
				w := WinUser{Name: windows.UTF16PtrToString(u.Name), Home: windows.UTF16PtrToString(u.HomeDir),
					Disabled: u.Flags&ufAccountDisable != 0, NoExpire: u.Flags&ufDontExpirePasswd != 0}
				if sid, _, _, err := windows.LookupSID("", w.Name); err == nil {
					w.SID = sid.String()
				}
				out = append(out, w)
			}
		}
		if buf != nil {
			windows.NetApiBufferFree(buf)
		}
		if err == nil {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// GroupMembers resolves the group's localized name from its SID first
// ("Administrators" is "Administratoren" on a German server).
func (l *Live) GroupMembers(sid string) ([]string, error) {
	s, err := windows.StringToSid(sid)
	if err != nil {
		return nil, winErr("StringToSid", sid, err)
	}
	name, _, _, err := s.LookupAccount("")
	if err != nil {
		return nil, winErr("LookupAccountSid", sid, err)
	}
	if err := procNetLocalGroupGetMembers.Find(); err != nil {
		return nil, winErr("NetLocalGroupGetMembers", sid, err)
	}
	gname, _ := windows.UTF16PtrFromString(name)
	var out []string
	var resume uintptr
	for {
		var buf *byte
		var read, total uint32
		r, _, _ := procNetLocalGroupGetMembers.Call(0, uintptr(unsafe.Pointer(gname)), 0, uintptr(unsafe.Pointer(&buf)),
			maxPreferredLength, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
		if r != nerrSuccess && r != errorMoreData {
			return nil, winErr("NetLocalGroupGetMembers", sid, syscall.Errno(r))
		}
		if buf != nil && read > 0 {
			for _, m := range unsafe.Slice((**windows.SID)(unsafe.Pointer(buf)), read) { // LOCALGROUP_MEMBERS_INFO_0
				out = append(out, m.String())
			}
		}
		if buf != nil {
			windows.NetApiBufferFree(buf)
		}
		if r == nerrSuccess {
			break
		}
	}
	sort.Strings(out)
	return out, nil
}

// ---- scheduled tasks ----

// MaxTasks caps how many task files are read.
const MaxTasks = 2000

// Tasks walks C:\Windows\System32\Tasks without following reparse points.
// Files are UTF-16; they are decoded and secret-masked before parsing.
func (l *Live) Tasks() ([]WinTask, error) {
	root := filepath.Join(os.Getenv("SystemRoot"), "System32", "Tasks")
	if os.Getenv("SystemRoot") == "" {
		root = `C:\Windows\System32\Tasks`
	}
	var out []WinTask
	var walk func(dir, rel string, depth int) error
	walk = func(dir, rel string, depth int) error {
		ents, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range ents {
			if len(out) >= MaxTasks {
				return ErrTruncated
			}
			p, r := filepath.Join(dir, e.Name()), rel+`\`+e.Name()
			switch {
			case e.Type()&fs.ModeSymlink != 0 || e.Type()&fs.ModeIrregular != 0:
				continue
			case e.IsDir():
				if depth < 8 {
					if err := walk(p, r, depth+1); err != nil && !errors.Is(err, fs.ErrPermission) {
						return err
					} else if err != nil {
						out = append(out, WinTask{Path: r, Err: errCode(err)})
					}
				}
			default:
				b, err := readTaskFile(p)
				if err != nil {
					out = append(out, WinTask{Path: r, Err: errCode(err)})
					continue
				}
				t, err := ParseTaskXML(r, []byte(MaskSecrets(DecodeText(b))))
				if err != nil {
					t.Err = "other:parse"
				}
				out = append(out, t)
			}
		}
		return nil
	}
	if err := walk(root, "", 0); err != nil {
		if errors.Is(err, ErrTruncated) {
			return out, err
		}
		return out, &fs.PathError{Op: "ReadDir", Path: root, Err: err}
	}
	return out, nil
}

func readTaskFile(p string) ([]byte, error) {
	f, err := openRead(p, true)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 1<<20))
}

// ---- event log ----

const (
	evtQueryChannelPath      = 0x1
	evtQueryReverseDirection = 0x200
	evtRenderEventXML        = 1
	errorNoMoreItems         = 259
	evtBatch                 = 64
)

func (l *Live) Events(channel, xpath string, max int) ([]WinEvent, error) {
	if err := procEvtQuery.Find(); err != nil {
		return nil, winErr("EvtQuery", channel, err)
	}
	ch, _ := windows.UTF16PtrFromString(channel)
	q, _ := windows.UTF16PtrFromString(xpath)
	rs, _, e := procEvtQuery.Call(0, uintptr(unsafe.Pointer(ch)), uintptr(unsafe.Pointer(q)), evtQueryChannelPath|evtQueryReverseDirection)
	if rs == 0 {
		return nil, winErr("EvtQuery", channel, e)
	}
	defer procEvtClose.Call(rs)
	var out []WinEvent
	handles := make([]uintptr, evtBatch)
	for len(out) < max {
		var got uint32
		r, _, e := procEvtNext.Call(rs, evtBatch, uintptr(unsafe.Pointer(&handles[0])), 5000, 0, uintptr(unsafe.Pointer(&got)))
		if r == 0 {
			if errno, ok := e.(syscall.Errno); ok && errno == errorNoMoreItems {
				break
			}
			return out, winErr("EvtNext", channel, e)
		}
		for _, h := range handles[:got] {
			if len(out) < max {
				if s, err := renderEvent(h); err == nil {
					if ev, err := ParseEventXML(s); err == nil {
						out = append(out, ev)
					}
				}
			}
			procEvtClose.Call(h)
		}
	}
	return out, nil
}

func renderEvent(h uintptr) (string, error) {
	size := uint32(8192)
	for tries := 0; tries < 3; tries++ {
		buf := make([]uint16, size/2)
		var used, props uint32
		r, _, e := procEvtRender.Call(0, h, evtRenderEventXML, uintptr(size), uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if r != 0 {
			return windows.UTF16ToString(buf[:used/2]), nil
		}
		if errno, ok := e.(syscall.Errno); !ok || errno != errInsufficientBuffer {
			return "", e
		}
		size = used + 2
	}
	return "", syscall.Errno(errInsufficientBuffer)
}
