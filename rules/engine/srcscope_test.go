package engine

import "testing"

// A route model's sources with extends (and no method) count only in a class
// extending that one: Elementor's get_settings() in a widget, through its
// parents in the file and in a project's other files; not in WP_Widget, a
// WooCommerce settings page, or code outside a class.
func TestRouteSourcesScoped(t *testing.T) {
	e := engineForTest(t)
	body := "\tpublic function render() {\n\t\tglobal $wpdb;\n\t\t$s = $this->get_settings();\n\t\techo $wpdb->get_var(\"SELECT n FROM t WHERE id = \" . $s['id']);\n\t}\n"
	for _, c := range []struct {
		name, src string
		want      bool
	}{
		{"an Elementor widget", "<?php\nclass W extends \\Elementor\\Widget_Base {\n" + body + "}\n", true},
		{"through a base in the file", "<?php\nclass B extends Widget_Base {}\nclass W extends B {\n" + body + "}\n", true},
		{"WP_Widget", "<?php\nclass W extends WP_Widget {\n" + body + "}\n", false},
		{"WooCommerce", "<?php\nclass W extends WC_Settings_Page {\n" + body + "}\n", false},
		{"no parent", "<?php\nclass W {\n" + body + "}\n", false},
	} {
		fs, err := e.Scan("php", "a.php", []byte(c.src))
		if err != nil || (len(fs) > 0) != c.want {
			t.Errorf("%s: %v (err %v), want reported %v", c.name, fs, err, c.want)
		}
	}
	// The widget's base class in another file of the project.
	files := map[string]string{
		"base.php": "<?php\nclass Box_Base extends \\Elementor\\Widget_Base {\n\tprotected function get_name() { return 'box'; }\n}\n",
		"w.php":    "<?php\nrequire 'base.php';\nclass W extends Box_Base {\n" + body + "}\n",
	}
	pr := e.NewProject([]string{"base.php", "w.php"}, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{})
	if fs, _ := pr.Scan("w.php", []byte(files["w.php"])); len(fs) == 0 {
		t.Error("base class in another file: not reported")
	}
}
