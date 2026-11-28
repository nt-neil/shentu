<?php
// parse_str with one argument sets variables of the scope. f() is not reported even after the engine fix: the include rule has no QUERY_STRING source (a rule-scope choice, left as is); g() is reported at :11.
function f() {
    $file = 'default.php';
    parse_str($_SERVER['QUERY_STRING']);
    include $file;
}
function g() {
    $file = 'default.php';
    extract($_GET);
    include $file;
}
