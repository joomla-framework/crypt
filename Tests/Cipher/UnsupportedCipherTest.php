<?php

/**
 * @copyright  Copyright (C) 2005 - 2021 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\Crypt\Tests\Cipher;

use Joomla\Crypt\Cipher\Crypto;
use Joomla\Crypt\Cipher\OpenSSL;
use Joomla\Crypt\Cipher\Sodium;
use Joomla\Crypt\CipherInterface;
use Joomla\Crypt\Exception\UnsupportedCipherException;
use Joomla\Crypt\Key;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tests the behaviour of the ciphers when they are not supported in the current environment.
 */
class UnsupportedCipherTest extends TestCase
{
    /**
     * Ciphers whose isSupported() reports false
     *
     * @return  array
     */
    public static function dataUnsupportedCiphers(): array
    {
        return [
            'Crypto'  => [
                new class () extends Crypto {
                    public static function isSupported(): bool
                    {
                        return false;
                    }
                },
                'crypto',
            ],
            'OpenSSL' => [
                new class ('1234567890123456', 'aes-128-cbc') extends OpenSSL {
                    public static function isSupported(): bool
                    {
                        return false;
                    }
                },
                'openssl',
            ],
            'Sodium'  => [
                new class () extends Sodium {
                    public static function isSupported(): bool
                    {
                        return false;
                    }
                },
                'sodium',
            ],
        ];
    }

    /**
     * @testdox  Encrypting with an unsupported cipher throws UnsupportedCipherException
     */
    #[DataProvider('dataUnsupportedCiphers')]
    public function testEncryptThrowsWhenUnsupported(CipherInterface $cipher, string $keyType)
    {
        $this->expectException(UnsupportedCipherException::class);

        $cipher->encrypt('data', new Key($keyType, str_repeat('a', 32), str_repeat('b', 32)));
    }

    /**
     * @testdox  Decrypting with an unsupported cipher throws UnsupportedCipherException
     */
    #[DataProvider('dataUnsupportedCiphers')]
    public function testDecryptThrowsWhenUnsupported(CipherInterface $cipher, string $keyType)
    {
        $this->expectException(UnsupportedCipherException::class);

        $cipher->decrypt('data', new Key($keyType, str_repeat('a', 32), str_repeat('b', 32)));
    }

    /**
     * @testdox  Generating a key with an unsupported cipher throws UnsupportedCipherException
     */
    #[DataProvider('dataUnsupportedCiphers')]
    public function testGenerateKeyThrowsWhenUnsupported(CipherInterface $cipher, string $keyType)
    {
        $this->expectException(UnsupportedCipherException::class);

        $cipher->generateKey(['passphrase' => 'passphrase']);
    }

    /**
     * @testdox  Sodium::isSupported() reflects the availability of the sodium functions
     */
    public function testSodiumIsSupportedChecksTheFunctions()
    {
        $this->assertSame(\function_exists('sodium_crypto_box'), Sodium::isSupported());
    }

    /**
     * @testdox  Without defuse/php-encryption the Crypto cipher is unsupported and throws UnsupportedCipherException
     */
    public function testCryptoWithoutDefuseLibrary()
    {
        exec(
            escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/stubs/crypto-without-defuse.php'),
            $output,
            $exitCode
        );

        $this->assertSame(0, $exitCode, implode(PHP_EOL, $output));
        $this->assertSame(
            [
                'isSupported' => false,
                'generateKey' => UnsupportedCipherException::class,
                'encrypt'     => UnsupportedCipherException::class,
                'decrypt'     => UnsupportedCipherException::class,
                'crypt'       => UnsupportedCipherException::class,
            ],
            json_decode(implode('', $output), true)
        );
    }
}
