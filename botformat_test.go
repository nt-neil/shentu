package main

import "testing"

func TestMarkdownToTelegramHTML(t *testing.T) {
	cases := map[string]string{
		"**伺服器狀態：需要注意**":                       "<b>伺服器狀態：需要注意</b>",
		"- 執行 `apt-get update && upgrade`":     "- 執行 <code>apt-get update &amp;&amp; upgrade</code>",
		"## 建議":                                "<b>建議</b>",
		"a *b* c ~~d~~":                        "a <i>b</i> c <s>d</s>",
		"* bullet":                             "* bullet",
		"<script>x</script> [l](http://e.vil)": "&lt;script&gt;x&lt;/script&gt; [l](http://e.vil)",
		"```\nls <dir>\n```":                   "<pre><code>ls &lt;dir&gt;</code></pre>",
		"unpaired ` tick **b**":                "unpaired ` tick <b>b</b>",
		"`**not bold**`":                       "<code>**not bold**</code>",
	}
	for in, want := range cases {
		if got := mdToTelegramHTML(in); got != want {
			t.Errorf("%q:\n got %q\nwant %q", in, got, want)
		}
	}
}
