<?php

// attempt to find Composer Autoloader
$vendorDir = __DIR__;
do {
    if (file_exists($file = $vendorDir.'/vendor/autoload.php')) {
        require_once $file;
        break;
    }
} while ($vendorDir = dirname($vendorDir));
