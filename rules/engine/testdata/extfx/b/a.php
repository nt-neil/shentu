<?php
// shortcode handler passes $atts to a helper that extracts and includes
add_shortcode('x', 'x_sc');
function x_sc($atts) { return x_eval('/safe/a.php', $atts); }
function x_eval($filepath, array $atts) {
    extract($atts);
    require_once $filepath;
}
