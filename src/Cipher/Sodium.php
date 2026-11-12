<?php

/**
 * Part of the Joomla Framework Crypt Package
 *
 * @copyright  Copyright (C) 2005 - 2021 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\Crypt\Cipher;

use Joomla\Crypt\CipherInterface;
use Joomla\Crypt\Exception\DecryptionException;
use Joomla\Crypt\Exception\EncryptionException;
use Joomla\Crypt\Exception\InvalidKeyException;
use Joomla\Crypt\Exception\InvalidKeyTypeException;
use Joomla\Crypt\Exception\UnsupportedCipherException;
use Joomla\Crypt\Key;
use ParagonIE\Sodium\Compat;

/**
 * Cipher for sodium algorithm encryption, decryption and key generation.
 *
 * @since  1.4.0
 */
class Sodium implements CipherInterface
{
    /**
     * Method to decrypt a data string.
     *
     * @param   string  $data  The encrypted string to decrypt.
     * @param   Key     $key   The key object to use for decryption.
     *
     * @return  string  The decrypted data string.
     *
     * @since   1.4.0
     * @throws  DecryptionException if the data cannot be decrypted
     * @throws  InvalidKeyTypeException if the key is not valid for the cipher
     */
    public function decrypt($data, Key $key)
    {
        // Validate key.
        if ($key->getType() !== 'sodium') {
            throw new InvalidKeyTypeException('sodium', $key->getType());
        }

        // The nonce is stored in front of the ciphertext
        if (\strlen($data) < SODIUM_CRYPTO_BOX_NONCEBYTES) {
            throw new DecryptionException('The encrypted data is too short to contain a nonce.');
        }

        $nonce = substr($data, 0, SODIUM_CRYPTO_BOX_NONCEBYTES);
        $data  = substr($data, SODIUM_CRYPTO_BOX_NONCEBYTES);

        try {
            $decrypted = sodium_crypto_box_open(
                $data,
                $nonce,
                sodium_crypto_box_keypair_from_secretkey_and_publickey($key->getPrivate(), $key->getPublic())
            );

            if ($decrypted === false) {
                throw new DecryptionException('Malformed message or invalid MAC');
            }
        } catch (\SodiumException $exception) {
            throw new DecryptionException('Malformed message or invalid MAC', $exception->getCode(), $exception);
        }

        return $decrypted;
    }

    /**
     * Method to encrypt a data string.
     *
     * @param   string  $data  The data string to encrypt.
     * @param   Key     $key   The key object to use for encryption.
     *
     * @return  string  The encrypted data string.
     *
     * @since   1.4.0
     * @throws  EncryptionException if the data cannot be encrypted
     * @throws  InvalidKeyTypeException if the key is not valid for the cipher
     */
    public function encrypt($data, Key $key)
    {
        // Validate key.
        if ($key->getType() !== 'sodium') {
            throw new InvalidKeyTypeException('sodium', $key->getType());
        }

        // Use a random nonce for every message and store it in front of the ciphertext
        $nonce = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);

        try {
            return $nonce . sodium_crypto_box(
                $data,
                $nonce,
                sodium_crypto_box_keypair_from_secretkey_and_publickey($key->getPrivate(), $key->getPublic())
            );
        } catch (\SodiumException $exception) {
            throw new EncryptionException('Could not encrypt data.', $exception->getCode(), $exception);
        }
    }

    /**
     * Method to generate a new encryption key object.
     *
     * @param   array  $options  Key generation options.
     *
     * @return  Key
     *
     * @since   1.4.0
     * @throws  InvalidKeyException if the key cannot be generated
     * @throws  UnsupportedCipherException if the cipher is not supported on the current environment
     */
    public function generateKey(array $options = [])
    {
        try {
            // Generate the encryption key.
            $pair = sodium_crypto_box_keypair();

            return new Key('sodium', sodium_crypto_box_secretkey($pair), sodium_crypto_box_publickey($pair));
        } catch (\SodiumException $exception) {
            throw new InvalidKeyException('Could not generate encryption key.', $exception->getCode(), $exception);
        }
    }

    /**
     * Check if the cipher is supported in this environment.
     *
     * @return  boolean
     *
     * @since   2.0.0
     */
    public static function isSupported(): bool
    {
        // Part of PHP since 7.2
        return true;
    }
}
