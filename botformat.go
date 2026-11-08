package main

import (
	"html"
	"regexp"
	"strings"
)

// The bot sends answers as Telegram HTML, converted from the small Markdown subset
// models use: code fences, headings, **bold**, *italic*, ~~strike~~ and `code`.
// Everything else is escaped, so the result always parses. Links are left as plain
// text on purpose: a [label](url) from the model could hide where it points.
var (
	mdBold   = regexp.MustCompile(`\*\*([^*\n]+?)\*\*`)
	mdStrike = regexp.MustCompile(`~~([^~\n]+?)~~`)
	mdItalic = regexp.MustCompile(`(^|[^*\w])\*([^*\s][^*\n]*?)\*($|[^*\w])`)
	mdHead   = regexp.MustCompile(`^#{1,6}\s+(.+)$`)
)

func mdToTelegramHTML(s string) string {
	var out []string
	inFence := false
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			if inFence {
				out = append(out, "</code></pre>")
			} else {
				out = append(out, "<pre><code>")
			}
			inFence = !inFence
			continue
		}
		if inFence {
			out = append(out, html.EscapeString(line))
			continue
		}
		if m := mdHead.FindStringSubmatch(line); m != nil {
			out = append(out, "<b>"+mdInline(m[1])+"</b>")
			continue
		}
		out = append(out, mdInline(line))
	}
	if inFence {
		out = append(out, "</code></pre>")
	}
	// A fence opens and closes on its own lines; join without the extra newlines.
	r := strings.Join(out, "\n")
	r = strings.ReplaceAll(r, "<pre><code>\n", "<pre><code>")
	return strings.ReplaceAll(r, "\n</code></pre>", "</code></pre>")
}

// mdInline formats one line; text inside `code` is not formatted further.
func mdInline(line string) string {
	parts := strings.Split(line, "`")
	if len(parts)%2 == 0 { // an unpaired backtick: keep it as text
		parts[len(parts)-2] += "`" + parts[len(parts)-1]
		parts = parts[:len(parts)-1]
	}
	var b strings.Builder
	for i, p := range parts {
		p = html.EscapeString(p)
		if i%2 == 1 {
			b.WriteString("<code>" + p + "</code>")
			continue
		}
		p = mdBold.ReplaceAllString(p, "<b>$1</b>")
		p = mdStrike.ReplaceAllString(p, "<s>$1</s>")
		p = mdItalic.ReplaceAllString(p, "$1<i>$2</i>$3")
		b.WriteString(p)
	}
	return b.String()
}
