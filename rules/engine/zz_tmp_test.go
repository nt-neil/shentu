package engine

import "testing"

func TestTmpCtx(t *testing.T) {
	e := engineForTest(t)
	for _, src := range []string{
		"<?php\n$s = remove_query_arg(array('a'), wp_get_referer());\n$s = add_query_arg(array('ids' => join(',', $_REQUEST['post'])), $s);\nwp_redirect($s);\n",
		"<?php\n$s = wp_get_referer();\n$s = add_query_arg('ids', $_REQUEST['post'], $s);\nwp_redirect($s);\n",
		"<?php\n$s = admin_url('x.php');\n$s = add_query_arg('ids', $_REQUEST['post'], $s);\nwp_redirect($s);\n",
		"<?php\nwp_redirect(add_query_arg('ids', $_REQUEST['post'], admin_url('x.php')));\n",
	} {
		fs, _ := e.Scan("php", "t.php", []byte(src))
		t.Logf("%q -> %d", src, len(fs))
	}
}
