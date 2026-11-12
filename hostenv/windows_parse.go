package hostenv

// Pure decoders for what the Windows APIs hand back: iphlpapi socket
// tables, rendered Event Log XML and Task Scheduler XML. They take bytes
// and return values, so they run and are tested on every OS.

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"net"
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
