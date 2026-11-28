<?php
// flags: EXTR_SKIP keeps $file (expected: not reported); EXTR_PREFIX_ALL too; EXTR_OVERWRITE reported
function s() {
    $file = 'default.php';
    extract($_GET, EXTR_SKIP);
    include $file;
}
function p() {
    $file = 'default.php';
    extract($_GET, EXTR_PREFIX_ALL, 'q');
    include $file;
}
function o() {
    $file = 'default.php';
    extract($_GET, EXTR_OVERWRITE);
    include $file;
}
