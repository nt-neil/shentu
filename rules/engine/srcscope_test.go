package engine

import "testing"

// A route model's sources with in_classes count on $this only in a class
// extending one of them: Elementor's get_settings() in a widget or a dynamic
// tag, through its parents in the file and in a project's other files; not in
// WP_Widget or a WooCommerce settings page. get_settings_for_display() counts
// on another object too; get_settings() (this_only) only on a skin's
// $this->parent: another object's may be a settings page's.
func TestRouteSourcesScoped(t *testing.T) {
	e := engineForTest(t)
	call := func(recv, m string) string {
		return "\tpublic function render() {\n\t\tglobal $wpdb;\n\t\t$s = " + recv + "->" + m + "();\n\t\techo $wpdb->get_var(\"SELECT n FROM t WHERE id = \" . $s['id']);\n\t}\n"
	}
	other := func(recv string) string { return call(recv, "get_settings") }
	display := func(recv string) string { return call(recv, "get_settings_for_display") }
	body := other("$this")
	for _, c := range []struct {
		name, src string
		want      bool
	}{
		{"an Elementor widget", "<?php\nclass W extends \\Elementor\\Widget_Base {\n" + body + "}\n", true},
		{"through a base in the file", "<?php\nclass B extends Widget_Base {}\nclass W extends B {\n" + body + "}\n", true},
		{"WP_Widget", "<?php\nclass W extends WP_Widget {\n" + body + "}\n", false},
		{"WooCommerce", "<?php\nclass W extends WC_Settings_Page {\n" + body + "}\n", false},
		{"no parent", "<?php\nclass W {\n" + body + "}\n", false},
		{"a dynamic tag", "<?php\nclass T extends \\Elementor\\Core\\DynamicTags\\Tag {\n" + body + "}\n", true},
		{"a data tag", "<?php\nclass T extends Elementor\\Core\\DynamicTags\\Data_Tag {\n" + body + "}\n", true},
		{"Class written in capitals", "<?php\nClass T extends \\Elementor\\Core\\DynamicTags\\Tag {\n" + body + "}\n", true},
		{"a skin, through its widget", "<?php\nclass S extends \\Elementor\\Skin_Base {\n" + other("$this->parent") + "}\n", true},
		{"a skin, for display", "<?php\nclass S extends \\Elementor\\Skin_Base {\n" + display("$this->parent") + "}\n", true},
		{"another object, for display", "<?php\nclass M {\n" + display("$element") + "}\n", true},
		{"another object, for display, in WP_Widget", "<?php\nclass W extends WP_Widget {\n" + display("$document") + "}\n", true},
		{"$this, for display, in WP_Widget", "<?php\nclass W extends WP_Widget {\n" + display("$this") + "}\n", false},
		{"another object's get_settings()", "<?php\nclass M {\n" + other("$section") + "}\n", false},
		{"another object's get_settings() in WP_Widget", "<?php\nclass W extends WP_Widget {\n" + other("$widget") + "}\n", false},
		{"$this's own property in a widget", "<?php\nclass W extends \\Elementor\\Widget_Base {\n" + other("$this->opts") + "}\n", false},
		{"a property of the skin's widget", "<?php\nclass S extends \\Elementor\\Skin_Base {\n" + other("$this->parent->opts") + "}\n", false},
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
