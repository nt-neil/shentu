package tools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withASP(t *testing.T) {
	t.Helper()
	a, f := aspAudit, foldPaths
	aspAudit, foldPaths = true, true
	t.Cleanup(func() { aspAudit, foldPaths = a, f })
}

func TestASPWebshellPatterns(t *testing.T) {
	withASP(t)
	bad := map[string]string{
		"chopper.asp":   `<%eval request("pass")%>`,
		"exec.asp":      `<% Execute(Request.Form("c")) %>`,
		"jscript.aspx":  `<%@ Page Language="Jscript"%><%eval(Request.Item["pass"],"unsafe");%>`,
		"wsh.asp":       `<% Set s = CreateObject("WScript.Shell") : Set o = s.Exec(Request("cmd")) %>`,
		"proc.aspx":     `<% System.Diagnostics.Process.Start("cmd.exe", "/c " + Request.Form["c"]); %>`,
		"psi.ashx":      `var psi = new ProcessStartInfo(); psi.FileName = Request["exe"];`,
		"loader.aspx":   `<% System.Reflection.Assembly.Load(Convert.FromBase64String(Request.Form["x"])).CreateInstance("U").Equals(this); %>`,
		"behinder.aspx": "byte[] c = Request.BinaryRead(Request.ContentLength);\nSystem.Reflection.Assembly.Load(new RijndaelManaged().CreateDecryptor(k, k).TransformFinalBlock(c, 0, c.Length)).CreateInstance(\"U\");",
	}
	for name, src := range bad {
		if aspWebshellAt(name, []byte(src)) < 0 {
			t.Errorf("%s not flagged: %s", name, src)
		}
	}
	good := map[string]string{
		"echo.aspx":    `<%= Server.HtmlEncode(Request.QueryString["name"]) %>`,
		"page.aspx":    `<% Server.Execute(Request["page"]); %>`,
		"notepad.aspx": `<% Process.Start("notepad.exe"); %>`,
		"lib.aspx":     `<% Assembly.Load("System.Web"); %>`,
		"form.asp":     `<% Response.Write(Request.Form("q")) %>`,
		"shell.php":    `<% eval request("pass") %>`, // not an IIS page type
	}
	for name, src := range good {
		if aspWebshellAt(name, []byte(src)) >= 0 {
			t.Errorf("%s flagged: %s", name, src)
		}
	}
	aspAudit = false
	if aspWebshellAt("chopper.asp", []byte(bad["chopper.asp"])) >= 0 || aspWebshellMatches("chopper.asp", []byte(bad["chopper.asp"])) != nil {
		t.Error("ASP patterns must stay off outside Windows")
	}
}

func TestASPCodeAudit(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "wwwroot")
	files := map[string]string{
		"default.aspx":     `<%= DateTime.Now %>`,
		"cmd.aspx":         `<%@ Page Language="Jscript"%><%eval(Request.Item["pass"],"unsafe");%>`,
		"Uploads/img.ashx": `<%@ WebHandler Language="C#" Class="H" %>`,
	}
	for p, c := range files {
		p = filepath.Join(root, filepath.FromSlash(p))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	kinds := func() map[string]bool {
		got := map[string]bool{}
		for _, f := range AppCodeAudit(context.Background(), []string{root}, []string{root}).Findings {
			got[f.Kind+" "+filepath.ToSlash(strings.TrimPrefix(f.Path, root+string(filepath.Separator)))] = true
		}
		return got
	}
	if got := kinds(); got["webshell cmd.aspx"] || got["upload_script Uploads/img.ashx"] {
		t.Errorf("Unix scans must not change: %v", got)
	}
	withASP(t)
	got := kinds()
	for _, k := range []string{"webshell cmd.aspx", "upload_script Uploads/img.ashx"} {
		if !got[k] {
			t.Errorf("missing %q in %v", k, got)
		}
	}
	if got["webshell default.aspx"] {
		t.Errorf("plain page flagged: %v", got)
	}
}

func TestSamePath(t *testing.T) {
	withASP(t)
	foldPaths = false
	if samePath("C:/inetpub/wwwroot", "c:/INETPUB/wwwroot") {
		t.Error("Unix paths are case-sensitive")
	}
	foldPaths = true
	if !samePath("C:/inetpub/wwwroot", "c:/INETPUB/wwwroot") {
		t.Error("Windows paths ignore case")
	}
}
