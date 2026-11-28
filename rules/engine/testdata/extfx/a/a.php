<?php
// shortcode handler, extract of its own $atts, then include
add_shortcode('x', 'x_sc');
function x_sc($atts) {
    $file = 'default.php';
    extract($atts);
    include $file;
}
