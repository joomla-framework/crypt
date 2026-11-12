<?php

/**
 * @copyright  Copyright (C) 2005 - 2021 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\Crypt\Tests;

use Joomla\Crypt\Cipher\Crypto;
use Joomla\Crypt\Cipher\OpenSSL;
use Joomla\Crypt\Cipher\Sodium;
use Joomla\Crypt\CipherInterface;
use Joomla\Crypt\Crypt;
use Joomla\Crypt\Key;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Checks the native types of the public API.
 */
class NativeTypesTest extends TestCase
{
    /**
     * Methods and their expected return types
     *
     * @return  array
     */
    public static function dataReturnTypes(): array
    {
        $cases = [
            'Crypt::decrypt()'       => [Crypt::class, 'decrypt', 'string'],
            'Crypt::encrypt()'       => [Crypt::class, 'encrypt', 'string'],
            'Crypt::generateKey()'   => [Crypt::class, 'generateKey', Key::class],
            'Crypt::setKey()'        => [Crypt::class, 'setKey', 'static'],
            'Crypt::genRandomBytes()' => [Crypt::class, 'genRandomBytes', 'string'],
        ];

        foreach ([CipherInterface::class, Crypto::class, OpenSSL::class, Sodium::class] as $class) {
            $short = substr($class, strrpos($class, chr(92)) + 1);

            $cases[$short . '::decrypt()']     = [$class, 'decrypt', 'string'];
            $cases[$short . '::encrypt()']     = [$class, 'encrypt', 'string'];
            $cases[$short . '::generateKey()'] = [$class, 'generateKey', Key::class];
        }

        return $cases;
    }

    /**
     * @testdox  The public API declares native return types
     *
     * @param   string  $class   The class name
     * @param   string  $method  The method name
     * @param   string  $type    The expected return type
     */
    #[DataProvider('dataReturnTypes')]
    public function testReturnType(string $class, string $method, string $type)
    {
        $this->assertSame($type, (string) (new \ReflectionMethod($class, $method))->getReturnType());
    }

    /**
     * @testdox  Non-string data is rejected instead of being coerced
     */
    public function testNullDataIsRejected()
    {
        $cipher = new Crypto();
        $crypt  = new Crypt($cipher, $cipher->generateKey());

        $this->expectException(\TypeError::class);

        $crypt->encrypt(null);
    }

    /**
     * @testdox  The length of random bytes must be an integer
     */
    public function testGenRandomBytesRequiresAnInteger()
    {
        $this->expectException(\TypeError::class);

        Crypt::genRandomBytes('sixteen');
    }
}
