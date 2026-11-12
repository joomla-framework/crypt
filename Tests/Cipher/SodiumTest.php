<?php

/**
 * @copyright  Copyright (C) 2005 - 2021 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\Crypt\Tests\Cipher;

use Joomla\Crypt\Cipher\Sodium;
use Joomla\Crypt\Exception\DecryptionException;
use Joomla\Crypt\Exception\EncryptionException;
use Joomla\Crypt\Exception\InvalidKeyTypeException;
use Joomla\Crypt\Key;
use ParagonIE\Sodium\Compat;
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
     * @testdox  Validates data is encrypted and decrypted correctly
     *
     * @param   string  $data  The decrypted data to validate
     *
     * @covers   \Joomla\Crypt\Cipher\Sodium
     * @uses     \Joomla\Crypt\Key
     */
    #[DataProvider('dataStrings')]
    public function testDataEncryptionAndDecryption($data)
    {
        $cipher = new Sodium();
        $key    = $cipher->generateKey();

        $cipher->setNonce(Compat::randombytes_buf(Compat::CRYPTO_BOX_NONCEBYTES));

        $encrypted = $cipher->encrypt($data, $key);

        // Assert that the encrypted value is not the same as the clear text value.
        $this->assertNotSame($data, $encrypted);

        $decrypted = $cipher->decrypt($encrypted, $key);

        // Assert the decrypted string is the same value we started with
        $this->assertSame($data, $decrypted);
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
     * @testdox  Encrypting with a key of the wrong type is rejected
     */
    public function testEncryptRejectsAKeyOfTheWrongType()
    {
        $cipher = new Sodium();
        $cipher->setNonce(Compat::randombytes_buf(Compat::CRYPTO_BOX_NONCEBYTES));

        $this->expectException(InvalidKeyTypeException::class);

        $cipher->encrypt('data', new Key('wrong', 'private', 'public'));
    }

    /**
     * @testdox  Decrypting with a key of the wrong type is rejected
     */
    public function testDecryptRejectsAKeyOfTheWrongType()
    {
        $cipher = new Sodium();
        $cipher->setNonce(Compat::randombytes_buf(Compat::CRYPTO_BOX_NONCEBYTES));

        $this->expectException(InvalidKeyTypeException::class);

        $cipher->decrypt('data', new Key('wrong', 'private', 'public'));
    }

    /**
     * @testdox  Encrypting without a nonce fails instead of using a default
     */
    public function testEncryptRequiresANonce()
    {
        $cipher = new Sodium();
        $key    = $cipher->generateKey();

        $this->expectException(EncryptionException::class);

        $cipher->encrypt('data', $key);
    }

    /**
     * @testdox  Decrypting without a nonce fails instead of using a default
     */
    public function testDecryptRequiresANonce()
    {
        $cipher = new Sodium();
        $key    = $cipher->generateKey();

        $this->expectException(DecryptionException::class);

        $cipher->decrypt('data', $key);
    }

    /**
     * @testdox  A tampered ciphertext is rejected rather than silently decrypted
     */
    public function testDecryptRejectsTamperedData()
    {
        $cipher = new Sodium();
        $key    = $cipher->generateKey();

        $cipher->setNonce(Compat::randombytes_buf(Compat::CRYPTO_BOX_NONCEBYTES));

        $encrypted = $cipher->encrypt('The quick brown fox', $key);

        // Flip the last byte of the ciphertext.
        $encrypted[\strlen($encrypted) - 1] = $encrypted[\strlen($encrypted) - 1] === 'a' ? 'b' : 'a';

        $this->expectException(DecryptionException::class);

        $cipher->decrypt($encrypted, $key);
    }

    /**
     * @testdox  Decrypting with a different key is rejected
     */
    public function testDecryptRejectsTheWrongKey()
    {
        $cipher = new Sodium();
        $nonce  = Compat::randombytes_buf(Compat::CRYPTO_BOX_NONCEBYTES);

        $cipher->setNonce($nonce);

        $encrypted = $cipher->encrypt('The quick brown fox', $cipher->generateKey());

        $this->expectException(DecryptionException::class);

        $cipher->decrypt($encrypted, $cipher->generateKey());
    }

    /**
     * @testdox  The cipher reports itself as supported in this environment
     */
    public function testIsSupported()
    {
        $this->assertTrue(Sodium::isSupported());
    }
}
