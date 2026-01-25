<?php
declare(strict_types=1);

/**
 * Namingo EPP Registrar module for WHMCS (https://www.whmcs.com/)
 * Minimal PSR-4 autoloader
 *
 */

if (!defined('PINGA_TEMBO_SRC_AUTOLOADED')) {
    define('PINGA_TEMBO_SRC_AUTOLOADED', true);

    spl_autoload_register(static function (string $class): void {
        $prefix  = 'Pinga\\Tembo\\';
        $baseDir = __DIR__ . '/src/';

        $len = strlen($prefix);
        if (strncmp($prefix, $class, $len) !== 0) {
            return;
        }

        $relativeClass = substr($class, $len);
        $file = $baseDir . str_replace('\\', '/', $relativeClass) . '.php';

        if (is_file($file)) {
            require $file;
        }
    }, true, true);
}