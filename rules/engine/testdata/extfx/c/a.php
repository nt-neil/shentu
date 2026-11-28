<?php
// same, but extract runs inside a closure that captures $filepath
add_shortcode('x', 'x_sc');
function x_sc($atts) { return x_eval('/safe/a.php', $atts); }
function x_eval($filepath, array $atts) {
    ( function( $atts ) use ( $filepath ) {
        extract( $atts );
        require_once $filepath;
    } )( $atts );
}
