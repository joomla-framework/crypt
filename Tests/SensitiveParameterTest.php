<?php

/**
 * @copyright  Copyright (C) 2005 - 2021 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\Crypt\Tests;

use Joomla\Crypt\Cipher\Crypto;
use Joomla\Crypt\Cipher\OpenSSL;
use Joomla\Crypt\Cipher\Sodium;
use Joomla\Crypt\Crypt;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Checks that parameters carrying key material are marked with #[\SensitiveParameter].
 */
class SensitiveParameterTest extends TestCase
{
    /**
     * Parameters that carry key material
     *
     * @return  array
     */
    public static function dataSensitiveParameters(): array
    {
        return [
            'Crypto::encrypt()'   => [Crypto::class, 'encrypt', 'key'],
            'Crypto::decrypt()'   => [Crypto::class, 'decrypt', 'key'],
            'OpenSSL::encrypt()'  => [OpenSSL::class, 'encrypt', 'key'],
            'OpenSSL::decrypt()'  => [OpenSSL::class, 'decrypt', 'key'],
            'OpenSSL::generateKey()' => [OpenSSL::class, 'generateKey', 'options'],
            'Sodium::encrypt()'   => [Sodium::class, 'encrypt', 'key'],
            'Sodium::decrypt()'   => [Sodium::class, 'decrypt', 'key'],
            'Crypt::__construct()' => [Crypt::class, '__construct', 'key'],
            'Crypt::setKey()'     => [Crypt::class, 'setKey', 'key'],
        ];
    }

    /**
     * @testdox  Key material is marked as sensitive so it is hidden in stack traces
     *
     * @param   string  $class      The class name
     * @param   string  $method     The method name
     * @param   string  $parameter  The parameter name
     */
    #[DataProvider('dataSensitiveParameters')]
    public function testParameterIsSensitive(string $class, string $method, string $parameter)
    {
        foreach ((new \ReflectionMethod($class, $method))->getParameters() as $reflection) {
            if ($reflection->getName() === $parameter) {
                $this->assertCount(1, $reflection->getAttributes(\SensitiveParameter::class));

                return;
            }
        }

        $this->fail("$class::$method() has no parameter \$$parameter");
    }
}
