package engine

import (
	"slices"
	"testing"
)

// HTML escaping inside a quoted string of a <script> body: the browser decodes
// no entity before the script runs, so a value with its quotes and < encoded
// (esc_attr, esc_html, esc_url) cannot leave the string, unless the string is
// in an on* handler (decoded first), a template literal (${ runs code), or a
// backslash at the value's end lets a later value on the line out
// (folders 3.0.1 includes/folders.class.php:1179, templates/admin/general-settings.php:221).
func TestScriptStringEscape(t *testing.T) {
	e := engineForTest(t)
	const rule = "php-xss-echo-script"
	for _, c := range []struct {
		name, src string
		want      []int
	}{
		{"esc_attr in a single-quoted string, folders' shape (no finding)",
			"<script>\nwindow.location = '<?php echo admin_url(\"edit.php\") . \"&s=\" . esc_attr($_GET['s']) ?>';\n</script>\n", nil},
		{"esc_url in a double-quoted string (no finding)",
			"<script>\nwindow.location = \"<?php echo esc_url($_GET['u']) ?>\";\n</script>\n", nil},
		{"esc_html in a var, short echo (no finding)",
			"<script>\nvar t = '<?= esc_html($_GET['t']) ?>';\n</script>\n", nil},
		{"htmlspecialchars with ENT_QUOTES (no finding)",
			"<script>\nvar t = '<?php echo htmlspecialchars($_GET['t'], ENT_QUOTES); ?>';\n</script>\n", nil},
		{"no escaping (control)",
			"<script>\nvar t = '<?php echo $_GET['t']; ?>';\n</script>\n", []int{2}},
		{"an on* handler decodes the entities first",
			"<button onclick=\"go('<?php echo esc_attr($_GET['t']); ?>')\">Go</button>\n", []int{1}},
		{"a template literal runs ${...}",
			"<script>\nvar t = `<?php echo esc_attr($_GET['t']) ?>`;\n</script>\n", []int{2}},
		{"a second value on the line: a backslash ending the first turns it into code",
			"<script>\nvar u = '<?php echo esc_attr($_GET['a']) ?>' + '<?php echo esc_attr($_GET['b']) ?>';\n</script>\n", []int{2}},
		{"a line continuation after the string",
			"<script>\nvar u = '<?php echo esc_attr($_GET['a']) ?>' + 'x\\\n<?php echo esc_attr($_GET['b']) ?>';\n</script>\n", []int{2}},
		{"the block writes a quote: the next value is outside the string",
			"<script>\nvar u = '<?php echo esc_attr($_GET['a']) . \"' + '\" . esc_attr($_GET['b']) ?>';\n</script>\n", []int{2}},
		{"htmlspecialchars without ENT_QUOTES leaves '",
			"<script>\nvar t = '<?php echo htmlspecialchars($_GET['t']); ?>';\n</script>\n", []int{2}},
		{"sanitize_text_field leaves quotes",
			"<script>\nvar t = '<?php echo sanitize_text_field($_GET['t']); ?>';\n</script>\n", []int{2}},
		{"not in a string",
			"<script>\nvar n = <?php echo esc_attr($_GET['n']); ?>;\n</script>\n", []int{2}},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := []byte(c.src)
			own, _, _ := e.ScanTimed("php", "a.php", src)
			var got []int
			for _, f := range own {
				if f.RuleID == rule {
					got = append(got, f.Line)
				}
			}
			slices.Sort(got)
			got = slices.Compact(got)
			if !slices.Equal(got, c.want) {
				t.Errorf("reported lines %v, want %v", got, c.want)
			}
		})
	}
}
