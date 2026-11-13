package tools

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"unicode/utf16"

	"github.com/nt-neil/shentu/hostenv"
)

// IIS support (Phase 2). Everything here is switched on for Windows only,
// so scans on Unix stay exactly as they were; tests flip the switches.
var (
	// aspAudit reads ASP and ASP.NET pages in the code audit and matches
	// them against aspWebshellPatterns.
	aspAudit = runtime.GOOS == "windows"
	// foldPaths compares web-root paths case-insensitively, as Windows does.
	foldPaths = runtime.GOOS == "windows"
	// winSource is the live Windows host the IIS web roots come from.
	winSource = func() hostenv.Source {
		l, err := hostenv.NewLive(hostenv.ForOS("windows").Allowlist())
		if err != nil {
			panic(err) // the allowlist is a constant; a bad one is a programming error
		}
		return l
	}
)

// aspExt are the page types IIS runs as code.
var aspExt = map[string]bool{".asp": true, ".aspx": true, ".ashx": true, ".asmx": true, ".cshtml": true}

// aspWebshellPatterns are classic ASP and ASP.NET webshell shapes: request
// data straight into eval/Execute, a shell, or an assembly loaded from the
// request (China Chopper, Behinder and Godzilla style loaders).
var aspWebshellPatterns = []*regexp.Regexp{
	// Not Server.Execute: that runs another page of the site, not code.
	regexp.MustCompile(`(?i)(?:^|[^.\w])(?:eval|execute|executeglobal)\s*\(?\s*request\s*[\.(\[]`),
	regexp.MustCompile(`(?i)wscript\.shell["']?\s*\)[\s\S]{0,300}?\.(?:exec|run)\s*\(\s*request\s*[\.(\[]`),
	regexp.MustCompile(`(?i)process\.start\s*\([^;]{0,200}?request\s*(?:\.(?:form|querystring|params|item|headers|cookies)|\[)`),
	regexp.MustCompile(`(?i)\.(?:filename|arguments)\s*=\s*request\s*(?:\.(?:form|querystring|params|item)|\[)`),
	regexp.MustCompile(`(?i)assembly\.load\s*\([^;]{0,300}?(?:request\.binaryread|request\s*\[|request\.(?:form|item|params)|convert\.frombase64string\s*\(\s*request)`),
	regexp.MustCompile(`(?i)request\.binaryread\s*\([\s\S]{0,400}?assembly\.load\s*\(`),
}

// aspText is the page as IIS reads it: UTF-16 (little- or big-endian,
// as Visual Studio can save it) and a UTF-8 BOM decoded, so a webshell
// cannot hide behind an encoding the byte-level patterns do not see.
func aspText(b []byte) []byte {
	if bytes.HasPrefix(b, []byte{0xFE, 0xFF}) {
		u := make([]uint16, (len(b)-2)/2)
		for i := range u {
			u[i] = binary.BigEndian.Uint16(b[2+2*i:])
		}
		return []byte(string(utf16.Decode(u)))
	}
	return []byte(hostenv.DecodeText(b))
}

// aspWebshellLine returns the 1-based line of the first ASP webshell
// pattern in a page IIS would run, or 0.
func aspWebshellLine(name string, b []byte) int {
	if !aspAudit || !aspExt[strings.ToLower(filepath.Ext(name))] {
		return 0
	}
	t := aspText(b)
	for _, re := range aspWebshellPatterns {
		if loc := re.FindIndex(t); loc != nil {
			return lineAt(t, loc[0])
		}
	}
	return 0
}

// aspWebshellMatches returns the matched text of every ASP webshell
// pattern found (for the hourly file-change scan).
func aspWebshellMatches(name string, b []byte) []string {
	if !aspAudit || !aspExt[strings.ToLower(filepath.Ext(name))] {
		return nil
	}
	t := aspText(b)
	var out []string
	for _, re := range aspWebshellPatterns {
		if m := re.Find(t); m != nil {
			out = append(out, string(m))
		}
	}
	return out
}

// aspPage reports a page the ASP checks read (on Windows only).
func aspPage(name string) bool {
	return aspAudit && aspExt[strings.ToLower(filepath.Ext(name))]
}

// samePath compares two slash-separated paths, ignoring case on Windows.
func samePath(a, b string) bool {
	if foldPaths {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// iisWebRoots returns the folders IIS serves and the configuration it
// could not read, from hostenv's applicationHost.config reader.
func iisWebRoots(src hostenv.Source) (roots, unreadable []string) {
	w := hostenv.WindowsCollector{}.Web(src)
	return w.Value.WebRoots, w.Value.ConfigUnreadable
}
