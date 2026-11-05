package tools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
)

var packageVulns = Tool{
	Name:        "package_vulns",
	Description: "Checks installed OS packages against the OSV vulnerability database (online, api.osv.dev). Without arguments returns affected packages and vulnerability IDs; with package set, returns the summary and severity of that package's vulnerabilities.",
	Params: schema(`{"type":"object","properties":{
		"package":{"type":"string","description":"show details for this package"}}}`),
	Run: func(ctx context.Context, env *Env, args json.RawMessage) (any, error) {
		var a struct {
			Package string `json:"package"`
		}
		if err := decode(args, &a); err != nil {
			return nil, err
		}
		return PackageVulns(ctx, env.HTTP, a.Package)
	},
}

type pkg struct{ Name, Version string }

const osvAPI = "https://api.osv.dev/v1"

// PackageVulns queries OSV for every installed package.
func PackageVulns(ctx context.Context, hc *http.Client, detailFor string) (map[string]any, error) {
	eco, pkgs, err := installedPackages(ctx)
	if err != nil {
		return nil, err
	}
	type query struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Version string `json:"version"`
	}
	type affected struct {
		Package string   `json:"package"`
		Version string   `json:"version"`
		IDs     []string `json:"ids"`
	}
	var found []affected
	total := 0
	for start := 0; start < len(pkgs); start += 500 {
		chunk := pkgs[start:min(start+500, len(pkgs))]
		qs := make([]query, len(chunk))
		for i, p := range chunk {
			qs[i].Package.Name, qs[i].Package.Ecosystem, qs[i].Version = p.Name, eco, p.Version
		}
		var resp struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			} `json:"results"`
		}
		if err := postJSON(ctx, hc, osvAPI+"/querybatch", map[string]any{"queries": qs}, &resp); err != nil {
			return nil, fmt.Errorf("OSV query failed (is the server online?): %w", err)
		}
		for i, r := range resp.Results {
			if len(r.Vulns) == 0 || i >= len(chunk) {
				continue
			}
			a := affected{Package: chunk[i].Name, Version: chunk[i].Version}
			for _, v := range r.Vulns {
				a.IDs = append(a.IDs, v.ID)
			}
			total += len(a.IDs)
			found = append(found, a)
		}
	}
	sort.Slice(found, func(i, j int) bool { return len(found[i].IDs) > len(found[j].IDs) })
	out := map[string]any{"ecosystem": eco, "packages_checked": len(pkgs), "affected_packages": len(found), "total_vulns": total}
	if detailFor == "" {
		if len(found) > 40 {
			found = found[:40]
			out["note"] = "only the 40 packages with the most vulnerabilities are listed"
		}
		out["affected"] = found
		return out, nil
	}
	type detail struct {
		ID       string `json:"id"`
		Summary  string `json:"summary"`
		Severity any    `json:"severity,omitempty"`
		Fixed    string `json:"fixed_version,omitempty"`
	}
	var details []detail
	for _, a := range found {
		if a.Package != detailFor {
			continue
		}
		for i, id := range a.IDs {
			if i >= 20 {
				break
			}
			var v struct {
				Summary  string `json:"summary"`
				Details  string `json:"details"`
				Severity any    `json:"severity"`
				Affected []struct {
					Ranges []struct {
						Events []map[string]string `json:"events"`
					} `json:"ranges"`
				} `json:"affected"`
			}
			if err := getJSON(ctx, hc, osvAPI+"/vulns/"+id, &v); err != nil {
				details = append(details, detail{ID: id, Summary: "details unavailable: " + err.Error()})
				continue
			}
			d := detail{ID: id, Summary: v.Summary, Severity: v.Severity}
			if d.Summary == "" {
				d.Summary = firstLine(v.Details, 200)
			}
			for _, af := range v.Affected {
				for _, r := range af.Ranges {
					for _, e := range r.Events {
						if f := e["fixed"]; f != "" {
							d.Fixed = f
						}
					}
				}
			}
			details = append(details, d)
		}
	}
	out["package"] = detailFor
	out["vulns"] = details
	return out, nil
}

// installedPackages detects the distro and lists packages in OSV naming.
func installedPackages(ctx context.Context) (string, []pkg, error) {
	osr := osRelease()
	id, ver := osr["ID"], osr["VERSION_ID"]
	switch id {
	case "ubuntu", "debian":
		eco := "Debian:" + strings.Split(ver, ".")[0]
		if id == "ubuntu" {
			eco = "Ubuntu:" + ver
			if strings.Contains(osr["VERSION"], "LTS") {
				eco += ":LTS"
			}
		}
		// OSV Debian/Ubuntu advisories use source package names.
		out, err := exec.CommandContext(ctx, "dpkg-query", "-W", "-f", "${source:Package}\t${Version}\t${db:Status-Abbrev}\n").Output()
		if err != nil {
			return "", nil, fmt.Errorf("dpkg-query: %w", err)
		}
		return eco, uniq(parseTSV(string(out), func(f []string) bool { return len(f) > 2 && strings.HasPrefix(f[2], "ii") })), nil
	case "alpine":
		parts := strings.Split(ver, ".")
		eco := "Alpine:v" + strings.Join(parts[:min(2, len(parts))], ".")
		b, err := os.ReadFile("/lib/apk/db/installed")
		if err != nil {
			return "", nil, err
		}
		var pkgs []pkg
		var name, version, origin string
		for _, l := range strings.Split(string(b)+"\n", "\n") {
			switch {
			case strings.HasPrefix(l, "P:"):
				name = l[2:]
			case strings.HasPrefix(l, "V:"):
				version = l[2:]
			case strings.HasPrefix(l, "o:"):
				origin = l[2:]
			case l == "":
				if origin == "" {
					origin = name
				}
				if origin != "" {
					pkgs = append(pkgs, pkg{origin, version})
				}
				name, version, origin = "", "", ""
			}
		}
		return eco, uniq(pkgs), nil
	case "rocky", "almalinux":
		eco := map[string]string{"rocky": "Rocky Linux", "almalinux": "AlmaLinux"}[id] + ":" + strings.Split(ver, ".")[0]
		out, err := exec.CommandContext(ctx, "rpm", "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n").Output()
		if err != nil {
			return "", nil, fmt.Errorf("rpm: %w", err)
		}
		return eco, uniq(parseTSV(string(out), nil)), nil
	}
	return "", nil, errors.New("unsupported distribution for package_vulns: " + id + " " + ver)
}

func parseTSV(s string, keep func([]string) bool) []pkg {
	var out []pkg
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 2 || f[0] == "" || (keep != nil && !keep(f)) {
			continue
		}
		out = append(out, pkg{f[0], f[1]})
	}
	return out
}

func uniq(in []pkg) []pkg {
	seen := map[pkg]bool{}
	var out []pkg
	for _, p := range in {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func osRelease() map[string]string {
	m := map[string]string{}
	b, _ := os.ReadFile("/etc/os-release")
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			m[k] = strings.Trim(v, `"`)
		}
	}
	return m
}

func firstLine(s string, n int) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

func postJSON(ctx context.Context, hc *http.Client, url string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return doJSON(hc, req, out)
}

func getJSON(ctx context.Context, hc *http.Client, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	return doJSON(hc, req, out)
}

func doJSON(hc *http.Client, req *http.Request, out any) error {
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s: HTTP %d", req.URL.Host, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
