<?php

/**
 * @copyright  Copyright (C) 2005 - 2021 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\Crypt\Tests;

use Joomla\Crypt\Cipher\Crypto;
use Joomla\Crypt\CipherInterface;
use Joomla\Crypt\Crypt;
use Joomla\Crypt\Key;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\IgnoreDeprecations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * Test class for \Joomla\Crypt\Crypt.
 */
class CryptTest extends TestCase
{
    /**
     * Cipher used for testing
     *
     * @var  MockObject|CipherInterface
     */
    private $cipher;

    /**
     * Generated key for testing
     *
     * @var  MockObject|Key
     */
    private $key;

    /**
     * Object under testing
     *
     * @var  Crypt
     */
    private $object;

    /**
     * Sets up the fixture, for example, opens a network connection.
     * This method is called before a test is executed.
     *
     * @return  void
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->cipher = $this->createMock(CipherInterface::class);
        $this->key    = $this->createMock(Key::class);

        $this->object = new Crypt($this->cipher, $this->key);
    }

    /**
     * @testdox  Validates data is encrypted and decrypted correctly
     *
     * @covers   \Joomla\Crypt\Crypt
     */
    public function testDataEncryptionAndDecryption()
    {
        $decrypted = 'decrypt';
        $encrypted = 'encrypt';

        $this->cipher->expects($this->once())
            ->method('encrypt')
            ->with($decrypted)
            ->willReturn($encrypted);

        $this->cipher->expects($this->once())
            ->method('decrypt')
            ->with($encrypted)
            ->willReturn($decrypted);

        $this->object->encrypt($decrypted);
        $this->object->decrypt($encrypted);
    }

    /**
     * @testdox  Validates keys are correctly generated
     *
     * @covers   \Joomla\Crypt\Crypt
     * @uses     \Joomla\Crypt\Key
     */
    public function testGenerateKey()
    {
        $this->cipher->expects($this->once())
            ->method('generateKey')
            ->willReturn($this->createMock(Key::class));

        $this->object->generateKey();
    }

    /**
     * @testdox  Validates a new key can be set
     *
     * @covers   \Joomla\Crypt\Crypt
     * @uses     \Joomla\Crypt\Key
     */
    public function testSetKey()
    {
        $key = $this->createMock(Key::class);

        $this->object->setKey($key);

        $property = (new \ReflectionClass($this->object))->getProperty('key');
        $property->setAccessible(true);

        $this->assertSame($key, $property->getValue($this->object));
    }

    /**
     * Test data for processing
     *
     * @return  array
     */
    public static function dataRandomByteLength(): array
    {
        return [
            '8 bytes' => [8],
            '16 bytes' => [16],
            '24 bytes' => [24],
            '32 bytes' => [32],
            '40 bytes' => [40],
        ];
    }

    /**
     * @testdox  Validates a string of random bytes of the requested size is returned
     *
     * @param    integer  $length  The length of the random string to generate
     *
     * @covers   \Joomla\Crypt\Crypt
     */
    #[DataProvider('dataRandomByteLength')]
    public function testGenRandomBytes($length)
    {
        $this->assertSame(
            $length,
            \strlen(Crypt::genRandomBytes($length))
        );
    }

    /**
     * Constructor arguments that rely on the deprecated defaults
     *
     * @return  array
     */
    public static function dataDeprecatedConstructorArguments(): array
    {
        return [
            'no arguments'  => [false, false],
            'no key'        => [true, false],
            'no cipher'     => [false, true],
        ];
    }

    /**
     * @testdox  Omitting the cipher or the key triggers a deprecation
     *
     * @param    boolean  $withCipher  Whether to pass a cipher
     * @param    boolean  $withKey     Whether to pass a key
     */
    #[AllowMockObjectsWithoutExpectations]
    #[DataProvider('dataDeprecatedConstructorArguments')]
    public function testConstructorWithoutCipherOrKeyTriggersDeprecation(bool $withCipher, bool $withKey)
    {
        $cipher = new Crypto();

        $this->expectUserDeprecationMessage(
            'Since joomla/crypt __DEPLOY_VERSION__: Calling Joomla\Crypt\Crypt::__construct() without a cipher and a key is deprecated.'
            . ' Both arguments will be required in 5.0.'
        );

        new Crypt($withCipher ? $cipher : null, $withKey ? $cipher->generateKey() : null);
    }

    /**
     * @testdox  The deprecated defaults still use the Crypto cipher with a generated key
     */
    #[AllowMockObjectsWithoutExpectations]
    #[IgnoreDeprecations]
    public function testConstructorDefaultsStillWork()
    {
        $crypt = new Crypt();

        $this->assertSame('data', $crypt->decrypt($crypt->encrypt('data')));
    }
}
