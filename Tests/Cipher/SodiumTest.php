<?php

/**
 * @copyright  Copyright (C) 2005 - 2021 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\Crypt\Tests\Cipher;

use Joomla\Crypt\Cipher\Sodium;
use Joomla\Crypt\Exception\DecryptionException;
use Joomla\Crypt\Key;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Polyfill\Util\Binary;

/**
 * Test class for \Joomla\Crypt\Cipher\Sodium.
 */
class SodiumTest extends TestCase
{
    /**
     * This method is called before the first test of this test class is run.
     *
     * @return  void
     */
    public static function setUpBeforeClass(): void
    {
        // Only run the test if the environment supports it.
        if (!Sodium::isSupported()) {
            self::markTestSkipped('The environment cannot safely perform encryption with this cipher.');
        }
    }

    /**
     * Test data for processing
     *
     * @return  array
     */
    public static function dataStrings(): array
    {
        return [
            ['c-;3-(Is>{DJzOHMCv_<#yKuN/G`/Us{GkgicWG$M|HW;kI0BVZ^|FY/"Obt53?PNaWwhmRtH;lWkWE4vlG5CIFA!abu&F=Xo#Qw}gAp3;GL\'k])%D}C+W&ne6_F$3P5'],
            ['Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. '
                . 'Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor '
                . 'in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt '
                . 'in culpa qui officia deserunt mollit anim id est laborum.'],
            ['لا أحد يحب الألم بذاته، يسعى ورائه أو يبتغيه، ببساطة لأنه الألم...'],
            ['Широкая электрификация южных губерний даст мощный толчок подъёму сельского хозяйства'],
            ['The quick brown fox jumps over the lazy dog.'],
        ];
    }

    /**
     * @testdox  Validates keys are correctly generated
     *
     * @covers   \Joomla\Crypt\Cipher\Sodium
     * @uses     \Joomla\Crypt\Key
     */
    public function testGenerateKey()
    {
        $cipher = new Sodium();
        $key    = $cipher->generateKey();

        // Assert that the key is the correct type.
        $this->assertInstanceOf(Key::class, $key);

        // Assert the keys pass validation
        $this->assertSame(Binary::strlen($key->getPrivate()), 32);
        $this->assertSame(Binary::strlen($key->getPublic()), 32);

        // Assert the key is of the correct type.
        $this->assertSame('sodium', $key->getType());
    }

    /**
     * @testdox  Validates data is encrypted and decrypted correctly with a random nonce per message
     *
     * @param   string  $data  The decrypted data to validate
     */
    #[DataProvider('dataStrings')]
    public function testDataEncryptionAndDecryptionWithoutNonce($data)
    {
        $cipher = new Sodium();
        $key    = $cipher->generateKey();

        $encrypted = $cipher->encrypt($data, $key);

        $this->assertNotSame($data, $encrypted);
        $this->assertSame($data, (new Sodium())->decrypt($encrypted, $key));
    }

    /**
     * @testdox  Encrypting the same message twice uses a different nonce each time
     */
    public function testEncryptUsesAFreshNonceForEveryMessage()
    {
        $cipher = new Sodium();
        $key    = $cipher->generateKey();

        $first  = $cipher->encrypt('The quick brown fox', $key);
        $second = $cipher->encrypt('The quick brown fox', $key);

        $this->assertNotSame($first, $second);
        $this->assertNotSame(substr($first, 0, SODIUM_CRYPTO_BOX_NONCEBYTES), substr($second, 0, SODIUM_CRYPTO_BOX_NONCEBYTES));

        // The nonce is stored in front of the crypto_box ciphertext
        $this->assertSame(
            'The quick brown fox',
            sodium_crypto_box_open(
                substr($first, SODIUM_CRYPTO_BOX_NONCEBYTES),
                substr($first, 0, SODIUM_CRYPTO_BOX_NONCEBYTES),
                sodium_crypto_box_keypair_from_secretkey_and_publickey($key->getPrivate(), $key->getPublic())
            )
        );
    }

    /**
     * @testdox  Data too short to contain a nonce is rejected
     */
    public function testDecryptRejectsDataWithoutNonce()
    {
        $cipher = new Sodium();
        $key    = $cipher->generateKey();

        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessage('The encrypted data is too short to contain a nonce.');

        $cipher->decrypt('data', $key);
    }

    /**
     * @testdox  The nonce can no longer be fixed
     */
    public function testNonceCannotBeSet()
    {
        $this->assertFalse(method_exists(Sodium::class, 'setNonce'));
    }
}
