<?php
// an immediately called closure: its parameter from the shortcode, no extract
add_shortcode('x', 'x_sc');
function x_sc($atts) {
    ( function( $a ) {
        require_once $a['f'];
    } )( $atts );
}
