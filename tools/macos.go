package tools

// package_vulns on macOS. OSV has no Homebrew or macOS application
// ecosystem, so the packages cannot be checked: the answer says so instead
// of reporting them clean. The OS itself is checked against Apple's public
// list of current software updates (the one Apple's device management
// reads), which names the newest release of each macOS major version.

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/nt-neil/shentu/hostenv"
)

// appleUpdatesURL is Apple's public software update catalogue; tests point
// it at a fake.
var appleUpdatesURL = "https://gdmf.apple.com/v2/pmv"

func macOSVulns(ctx context.Context, hc *http.Client) (map[string]any, error) {
	src := hostSource()
	mac := hostenv.DarwinCollector{}
	plat := mac.Platform(ctx, src, nil)
	if plat.Value.Version == "" {
		return nil, fmt.Errorf("macOS version unknown: %s", plat.Detail)
	}
	set := mac.Packages(src, plat.Value.Version)
	out := map[string]any{
		"os":               plat.Value.PrettyName,
		"packages_checked": 0,
		"packages":         fmt.Sprintf("cannot tell: %d Homebrew formulae, casks and applications are installed, but no public vulnerability feed covers them (OSV has no Homebrew ecosystem)", len(set.Value.Items)),
		"upgrade_command":  "softwareupdate --install --all",
	}
	var cat struct {
		PublicAssetSets struct {
			MacOS []struct {
				ProductVersion string
				PostingDate    string
			} `json:"macOS"`
		}
	}
	if err := getJSON(ctx, hc, appleUpdatesURL, &cat); err != nil {
		out["os_updates"] = "cannot tell: Apple's software update list unavailable (is the Mac online?): " + err.Error()
		return out, nil
	}
	major := strings.Split(plat.Value.Version, ".")[0]
	latest, newestMajor := "", 0
	for _, a := range cat.PublicAssetSets.MacOS {
		m := strings.Split(a.ProductVersion, ".")[0]
		if n, err := strconv.Atoi(m); err == nil && n > newestMajor {
			newestMajor = n
		}
		if m == major && compareVersions(a.ProductVersion, latest) > 0 {
			latest = a.ProductVersion
		}
	}
	hostMajor, _ := strconv.Atoi(major)
	switch {
	case newestMajor == 0: // an empty or unreadable list says nothing either way
		out["os_updates"] = "cannot tell: Apple's software update list named no macOS release"
	case hostMajor > newestMajor: // newer than any release: a beta
		out["os_updates"] = fmt.Sprintf("cannot tell: macOS %s is newer than every release on Apple's list (macOS %d is the newest), so it is likely a beta; betas get their fixes as new betas", plat.Value.Version, newestMajor)
	case latest != "" && compareVersions(plat.Value.Version, latest) > 0:
		out["os_updates"] = fmt.Sprintf("cannot tell: macOS %s is newer than %s, the newest release Apple lists, so it is likely a beta", plat.Value.Version, latest)
	case latest == "":
		out["os_updates"] = fmt.Sprintf("macOS %s is not on Apple's list of current releases: it no longer gets security updates; upgrade to macOS %d", major, newestMajor)
		out["os_up_to_date"] = false
	case compareVersions(plat.Value.Version, latest) < 0:
		out["os_updates"] = fmt.Sprintf("macOS %s is installed; %s is out with security fixes", plat.Value.Version, latest)
		out["os_up_to_date"] = false
	default:
		out["os_updates"] = fmt.Sprintf("macOS %s is the newest release of macOS %s", plat.Value.Version, major)
		out["os_up_to_date"] = true
	}
	out["latest_in_major"] = latest
	if hostMajor > 0 && newestMajor-hostMajor >= 2 {
		out["os_support"] = fmt.Sprintf("macOS %d is two or more versions behind macOS %d; Apple fixes only some vulnerabilities in older versions", hostMajor, newestMajor)
	}
	return out, nil
}

// compareVersions compares dotted numbers ("27.2.1" > "27.2"); "" is lowest.
func compareVersions(a, b string) int {
	if a == b {
		return 0
	}
	if b == "" {
		return 1
	}
	if a == "" {
		return -1
	}
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < max(len(as), len(bs)); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
