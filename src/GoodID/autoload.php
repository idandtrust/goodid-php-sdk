<?php

if (version_compare(PHP_VERSION, '5.6', '<')) {
    throw new Exception('The GoodID SDK requires PHP version 5.6 or higher.');
}

/**
 * Register the autoloader for the GoodID SDK classes.
 *
 * @param string $class
 *
 * @return void
 */
spl_autoload_register(function ($class) {
    // namespace prefix
    $prefix = 'GoodID\\';

    // For backwards compatibility
    $customBaseDir = '';

    if (defined('GOODID_SRC_DIR')) {
        $customBaseDir = GOODID_SRC_DIR;
    }
    // base directory for the namespace prefix
    $baseDir = $customBaseDir ?: __DIR__ . '/';

    // does the class use the namespace prefix?
    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        // no, move to the next registered autoloader
        return;
    }

    // get the relative class name
    $relativeClass = substr($class, $len);

    // replace the namespace prefix with the base directory, replace namespace
    // separators with directory separators in the relative class name, append
    // with .php
    $file = rtrim($baseDir, '/') . '/' . str_replace('\\', '/', $relativeClass) . '.php';

    // if the file exists, require it
    if (file_exists($file)) {
        require $file;
    }
});
