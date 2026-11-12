<?php

/**
 * @copyright  Copyright (C) 2005 - 2021 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\Crypt\Tests;

use Joomla\Crypt\Key;
use PHPUnit\Framework\TestCase;

/**
 * Test class for \Joomla\Crypt\Key.
 */
class KeyTest extends TestCase
{
    /**
     * Object under testing
     *
     * @var  Key
     */
    private $object;

    /**
     * Private key for the test object
     *
     * @var string
     */
    private $private = 'private';

    /**
     * Public key for the test object
     *
     * @var string
     */
    private $public = 'public';

    /**
     * Key type for the test object
     *
     * @var string
     */
    private $type = 'test';

    /**
     * Sets up the fixture, for example, opens a network connection.
     * This method is called before a test is executed.
     *
     * @return  void
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->type    = 'test';
        $this->public  = 'public';
        $this->private = 'private';

        $this->object = new Key($this->type, $this->private, $this->public);
    }

    /**
     * @testdox  Validates the private key is returned
     *
     * @covers   Joomla\Crypt\Key
     */
    public function testGetPrivate()
    {
        $this->assertSame($this->private, $this->object->getPrivate());
    }

    /**
     * @testdox  Validates the public key is returned
     *
     * @covers   Joomla\Crypt\Key
     */
    public function testGetPublic()
    {
        $this->assertSame($this->public, $this->object->getPublic());
    }

    /**
     * @testdox  Validates the key type is returned
     *
     * @covers   Joomla\Crypt\Key
     */
    public function testGetKeyType()
    {
        $this->assertSame($this->type, $this->object->getType());
    }

    /**
     * @testdox  Debugging output does not contain the key material
     */
    public function testDebugOutputIsRedacted()
    {
        $key = new Key('test', 'secret-private-material', 'secret-public-material');

        ob_start();
        var_dump($key);
        $dump = ob_get_clean();

        $printed = print_r($key, true);

        foreach ([$dump, $printed] as $output) {
            $this->assertStringContainsString('test', $output);
            $this->assertStringNotContainsString('secret-', $output);
        }
    }

    /**
     * @testdox  The private key is not exposed in stack traces
     */
    public function testPrivateKeyIsSensitiveParameter()
    {
        $parameter = (new \ReflectionMethod(Key::class, '__construct'))->getParameters()[1];

        $this->assertSame('private', $parameter->getName());
        $this->assertCount(1, $parameter->getAttributes(\SensitiveParameter::class));
    }
}
