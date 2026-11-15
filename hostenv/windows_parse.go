package hostenv

// Pure decoders for what the Windows APIs hand back: iphlpapi socket
// tables, rendered Event Log XML and Task Scheduler XML. They take bytes
// and return values, so they run and are tested on every OS.

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode/utf16"
)

var errShortTable = errors.New("hostenv: socket table shorter than its row count")

// Row sizes of the OWNER_PID tables (iphlpapi.h).
const (
	tcp4RowSize = 24 // MIB_TCPROW_OWNER_PID
	tcp6RowSize = 56 // MIB_TCP6ROW_OWNER_PID
	udp4RowSize = 12 // MIB_UDPROW_OWNER_PID
	udp6RowSize = 28 // MIB_UDP6ROW_OWNER_PID
)

var tcpStates = map[uint32]string{1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED",
	6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB"}

// netPort reads a DWORD port field: the port is in network byte order in
// its low 16 bits.
func netPort(b []byte) int { return int(binary.BigEndian.Uint16(b[:2])) }

// ParseSocketTable decodes a GetExtendedTcpTable (TCP_TABLE_OWNER_PID_*)
// or GetExtendedUdpTable (UDP_TABLE_OWNER_PID) buffer. proto is tcp, tcp6,
// udp or udp6. The buffer starts with a DWORD row count.
func ParseSocketTable(proto string, b []byte) ([]WinSocket, error) {
	if len(b) < 4 {
		return nil, errShortTable
	}
	n := int(binary.LittleEndian.Uint32(b))
	size := map[string]int{"tcp": tcp4RowSize, "tcp6": tcp6RowSize, "udp": udp4RowSize, "udp6": udp6RowSize}[proto]
	if size == 0 {
		return nil, errors.New("hostenv: unknown socket table " + proto)
	}
	rows := b[4:]
	if n < 0 || len(rows) < n*size {
		return nil, errShortTable
	}
	out := make([]WinSocket, 0, n)
	for i := 0; i < n; i++ {
		r := rows[i*size : (i+1)*size]
		s := WinSocket{Proto: proto}
		switch proto {
		case "tcp": // state, local addr, local port, remote addr, remote port, pid
			s.State = tcpStates[binary.LittleEndian.Uint32(r[0:])]
			s.Addr = net.IP(r[4:8]).String()
			s.Port = netPort(r[8:])
			s.OwnerPID = int(binary.LittleEndian.Uint32(r[20:]))
		case "tcp6": // local addr[16], scope, port, remote addr[16], scope, port, state, pid
			s.Addr = net.IP(r[0:16]).String()
			s.Port = netPort(r[20:])
			s.State = tcpStates[binary.LittleEndian.Uint32(r[48:])]
			s.OwnerPID = int(binary.LittleEndian.Uint32(r[52:]))
		case "udp": // local addr, local port, pid
			s.Addr = net.IP(r[0:4]).String()
			s.Port = netPort(r[4:])
			s.OwnerPID = int(binary.LittleEndian.Uint32(r[8:]))
		case "udp6": // local addr[16], scope, port, pid
			s.Addr = net.IP(r[0:16]).String()
			s.Port = netPort(r[20:])
			s.OwnerPID = int(binary.LittleEndian.Uint32(r[24:]))
		}
		out = append(out, s)
	}
	return out, nil
}

// DecodeText returns b as UTF-8, decoding UTF-16 (with or without a BOM, as
// Task Scheduler writes it) and dropping a UTF-8 BOM.
func DecodeText(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}):
		return string(b[3:])
	case bytes.HasPrefix(b, []byte{0xFF, 0xFE}):
		return utf16le(b[2:])
	case len(b) >= 4 && b[1] == 0 && b[3] == 0 && b[0] != 0:
		return utf16le(b) // "<\0?\0" without a BOM
	}
	return string(b)
}

func utf16le(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// nameValue is any element with a Name attribute and text, as in
// <Data Name="IpAddress">10.0.0.5</Data>.
type nameValue struct {
	XMLName xml.Name
	Name    string `xml:"Name,attr"`
	Value   string `xml:",chardata"`
}

type eventXML struct {
	System struct {
		EventID     int    `xml:"EventID"`
		Channel     string `xml:"Channel"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []nameValue `xml:"Data"`
	} `xml:"EventData"`
	UserData struct {
		Inner struct {
			Fields []nameValue `xml:",any"`
		} `xml:",any"`
	} `xml:"UserData"`
}

// eventFields are the EventData/UserData fields winAuthEvents uses.
var eventFields = map[string]bool{"IpAddress": true, "LogonType": true, "SubjectUserName": true,
	"TargetUserName": true, "MemberSid": true, "ServiceName": true}

// ParseEventXML decodes one event rendered with EvtRenderEventXml. EventData
// fields are keyed by their Name attribute, UserData fields (1102, 104) by
// their element name. Values are secret-masked.
func ParseEventXML(s string) (WinEvent, error) {
	var x eventXML
	if err := xml.Unmarshal([]byte(s), &x); err != nil {
		return WinEvent{}, err
	}
	e := WinEvent{Channel: x.System.Channel, ID: x.System.EventID, Time: x.System.TimeCreated.SystemTime, Data: map[string]string{}}
	for _, d := range x.EventData.Data {
		if d.Name != "" {
			e.Data[d.Name] = MaskSecrets(strings.TrimSpace(d.Value))
		}
	}
	for _, d := range x.UserData.Inner.Fields {
		e.Data[d.XMLName.Local] = MaskSecrets(strings.TrimSpace(d.Value))
	}
	for k := range e.Data {
		// Only fields the collector reads leave the source. A failed logon's
		// TargetUserName is whatever was typed, sometimes a password.
		if !eventFields[k] || (e.ID == 4625 && k == "TargetUserName") {
			delete(e.Data, k)
		}
	}
	if len(e.Data) == 0 {
		e.Data = nil
	}
	return e, nil
}

// typedNameEvents are the events whose user and domain fields hold what
// someone typed at a logon that failed, or the credentials they named:
// sometimes a password. Kerberos pre-authentication (4771), ticket
// requests (4768), NTLM validation (4776), explicit credentials (4648),
// failed logons (4625).
var typedNameEvents = map[int]bool{4625: true, 4648: true, 4768: true, 4771: true, 4776: true}

// typedNameFields are dropped from those events.
var typedNameFields = map[string]bool{"TargetUserName": true, "TargetDomainName": true, "TargetOutboundUserName": true,
	"TargetOutboundDomainName": true, "Workstation": true}

// sshNameWord starts the part of an OpenSSH message that names a user
// ("for X", "user X"); sshAddr is the source address and port.
var (
	sshNameWord = regexp.MustCompile(`(?i)\b(?:for|user)\b`)
	sshAddr     = regexp.MustCompile(`(?i)\b((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]*:[0-9a-f:.]+)\s+port\s+(\d+)`)
)

// sshSkeleton keeps of an OpenSSH message that names a user only what it
// did, the source and port: "Failed password [name] from 203.0.113.9 port
// 22". Default deny: a name may hold spaces or look like anything, so
// everything after the first "for"/"user" goes, whatever its layout.
func sshSkeleton(v string) string {
	loc := sshNameWord.FindStringIndex(v)
	if loc == nil {
		return v
	}
	out := strings.TrimSpace(v[:loc[0]]) + " [name]"
	// The name comes first and may itself spell "<ip> port <n>": sshd's own
	// source is the last address in the message.
	if all := sshAddr.FindAllStringSubmatch(v[loc[0]:], -1); len(all) > 0 {
		m := all[len(all)-1]
		out += " from " + m[1] + " port " + m[2]
	}
	if strings.Contains(v, "[preauth]") {
		out += " [preauth]"
	}
	return out
}

// ParseEventText renders one event (EvtRenderEventXml) as one searchable
// line: time, channel, ID and every EventData/UserData field as
// Name=value, secret-masked (command lines included: they are worth
// searching, and MaskSecrets takes the credentials out). What someone
// typed at a failed logon never appears: the typed-name fields of
// typedNameEvents are dropped, and OpenSSH's messages that name a user are
// cut to a skeleton (sshSkeleton).
func ParseEventText(s string) (string, error) {
	var x eventXML
	if err := xml.Unmarshal([]byte(s), &x); err != nil {
		return "", err
	}
	ssh := strings.HasPrefix(x.System.Channel, "OpenSSH")
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %d:", x.System.TimeCreated.SystemTime, x.System.Channel, x.System.EventID)
	field := func(name, value string) {
		if name == "" || typedNameEvents[x.System.EventID] && typedNameFields[name] {
			return
		}
		value = strings.Join(strings.Fields(value), " ")
		if ssh {
			value = sshSkeleton(value)
		}
		fmt.Fprintf(&b, " %s=%s", name, value)
	}
	for _, d := range x.EventData.Data {
		field(d.Name, d.Value)
	}
	for _, d := range x.UserData.Inner.Fields {
		field(d.XMLName.Local, d.Value)
	}
	return MaskSecrets(b.String()), nil
}

type taskXML struct {
	Settings struct {
		Enabled string `xml:"Enabled"`
	} `xml:"Settings"`
	Principals struct {
		Principal []struct {
			UserID    string `xml:"UserId"`
			GroupID   string `xml:"GroupId"`
			RunLevel  string `xml:"RunLevel"`
			LogonType string `xml:"LogonType"`
		} `xml:"Principal"`
	} `xml:"Principals"`
	Triggers struct {
		Any []struct {
			XMLName xml.Name
			Enabled string `xml:"Enabled"`
		} `xml:",any"`
	} `xml:"Triggers"`
	Actions struct {
		Exec []struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
		ComHandler []struct {
			ClassID string `xml:"ClassId"`
		} `xml:"ComHandler"`
	} `xml:"Actions"`
}

// ParseTaskXML decodes a Task Scheduler 1.2+ definition. The file is
// usually UTF-16 with an encoding="UTF-16" declaration; DecodeText has
// already turned it into UTF-8, so the declaration is ignored.
func ParseTaskXML(path string, b []byte) (WinTask, error) {
	s := DecodeText(b)
	if i := strings.Index(s, "?>"); strings.HasPrefix(strings.TrimSpace(s), "<?xml") && i >= 0 {
		s = s[i+2:]
	}
	var x taskXML
	if err := xml.Unmarshal([]byte(s), &x); err != nil {
		return WinTask{Path: path}, err
	}
	t := WinTask{Path: path, Enabled: !strings.EqualFold(strings.TrimSpace(x.Settings.Enabled), "false")}
	if len(x.Principals.Principal) > 0 {
		p := x.Principals.Principal[0]
		t.RunAs = strings.TrimSpace(p.UserID)
		if t.RunAs == "" {
			t.RunAs = strings.TrimSpace(p.GroupID)
		}
		if strings.EqualFold(p.RunLevel, "HighestAvailable") {
			t.RunAs += " (highest)"
		}
	}
	for _, tr := range x.Triggers.Any {
		if !strings.EqualFold(strings.TrimSpace(tr.Enabled), "false") {
			t.Triggers = append(t.Triggers, tr.XMLName.Local)
		}
	}
	for _, a := range x.Actions.Exec {
		cmd := strings.TrimSpace(a.Command)
		if args := strings.TrimSpace(a.Arguments); args != "" {
			cmd += " " + args
		}
		t.Actions = append(t.Actions, capCmdline(cmd))
	}
	for _, c := range x.Actions.ComHandler {
		t.Actions = append(t.Actions, "com:"+strings.TrimSpace(c.ClassID))
	}
	return t, nil
}

// ParseIISConfig returns the physical paths of every virtual directory in
// an applicationHost.config, in file order, with %SystemDrive%, %windir%
// and %SystemRoot% expanded from systemRoot (e.g. C:\Windows). Other
// environment variables are left as written. The site defaults
// (<virtualDirectoryDefaults>) are not virtual directories and are skipped.
func ParseIISConfig(b []byte, systemRoot string) ([]string, error) {
	var cfg struct {
		Sites []struct {
			Apps []struct {
				Dirs []struct {
					PhysicalPath string `xml:"physicalPath,attr"`
				} `xml:"virtualDirectory"`
			} `xml:"application"`
		} `xml:"system.applicationHost>sites>site"`
	}
	if err := xml.Unmarshal(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), &cfg); err != nil {
		return nil, err
	}
	drive := "C:"
	if len(systemRoot) >= 2 && systemRoot[1] == ':' {
		drive = systemRoot[:2]
	}
	var out []string
	for _, s := range cfg.Sites {
		for _, a := range s.Apps {
			for _, d := range a.Dirs {
				p := strings.TrimSpace(d.PhysicalPath)
				if p == "" {
					continue
				}
				p = expandWinVar(p, "SystemDrive", drive)
				p = expandWinVar(p, "windir", systemRoot)
				p = expandWinVar(p, "SystemRoot", systemRoot)
				out = append(out, strings.TrimRight(p, `\`))
			}
		}
	}
	return out, nil
}

// expandWinVar replaces %name% (any case) with val.
func expandWinVar(s, name, val string) string {
	tok := "%" + strings.ToLower(name) + "%"
	for {
		i := strings.Index(strings.ToLower(s), tok)
		if i < 0 {
			return s
		}
		s = s[:i] + val + s[i+len(tok):]
	}
}
