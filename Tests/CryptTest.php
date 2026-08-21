<?php

/**
 * @copyright  Copyright (C) 2005 - 2021 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\Crypt\Tests;

use Joomla\Crypt\CipherInterface;
use Joomla\Crypt\Crypt;
use Joomla\Crypt\Key;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * Test class for \Joomla\Crypt\Crypt.
 */
#[CoversClass(Crypt::class)]
#[UsesClass(Key::class)]
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

    #[TestDox('Validates data is encrypted and decrypted correctly')]
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

    #[TestDox('Validates keys are correctly generated')]
    public function testGenerateKey()
    {
        $this->cipher->expects($this->once())
            ->method('generateKey')
            ->willReturn($this->createMock(Key::class));

        $this->object->generateKey();
    }

    #[TestDox('Validates a new key can be set')]
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
     * @param    integer  $length  The length of the random string to generate
     */
    #[DataProvider('dataRandomByteLength')]
    #[TestDox('Validates a string of random bytes of the requested size is returned')]
    public function testGenRandomBytes($length)
    {
        $this->assertSame(
            $length,
            \strlen(Crypt::genRandomBytes($length))
        );
    }
}
