<?php

/**
 * Runs the Crypto cipher as if defuse/php-encryption were not installed: only the package's own classes can be
 * autoloaded. Prints the results as JSON.
 *
 * @copyright  Copyright (C) 2005 - 2021 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

spl_autoload_register(
    static function (string $class): void {
        $prefix = 'Joomla\Crypt\\';

        if (strpos($class, $prefix) === 0) {
            require dirname(__DIR__, 3) . '/src/' . str_replace(chr(92), '/', substr($class, strlen($prefix))) . '.php';
        }
    }
);

$result = ['isSupported' => Joomla\Crypt\Cipher\Crypto::isSupported()];

$calls = [
    'generateKey' => static fn () => (new Joomla\Crypt\Cipher\Crypto())->generateKey(),
    'encrypt'     => static fn () => (new Joomla\Crypt\Cipher\Crypto())->encrypt('data', new Joomla\Crypt\Key('crypto', 'private', '')),
    'decrypt'     => static fn () => (new Joomla\Crypt\Cipher\Crypto())->decrypt('data', new Joomla\Crypt\Key('crypto', 'private', '')),
    'crypt'       => static fn () => new Joomla\Crypt\Crypt(),
];

foreach ($calls as $name => $callback) {
    try {
        $callback();
        $result[$name] = 'no exception';
    } catch (Throwable $e) {
        $result[$name] = get_class($e);
    }
}

echo json_encode($result);
