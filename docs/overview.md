# Overview

The Crypt package provides symmetric encryption behind a common cipher interface, plus a key object
and a set of typed exceptions.

```bash
composer require joomla/crypt
```

## What is in the package

| Class | Purpose |
|---|---|
| `Joomla\Crypt\Crypt` | Pairs a cipher with a key and exposes `encrypt()`, `decrypt()`, `generateKey()` |
| `Joomla\Crypt\CipherInterface` | The cipher contract |
| `Joomla\Crypt\Cipher\Crypto` | Wrapper around `defuse/php-encryption` — **the one to use** |
| `Joomla\Crypt\Cipher\Sodium` | libsodium `crypto_box` |
| `Joomla\Crypt\Cipher\OpenSSL` | ext-openssl — see the warning below |
| `Joomla\Crypt\Key` | Holds a key type plus the private and public key material |
| `Joomla\Crypt\Exception\*` | `CryptExceptionInterface` and five concrete exceptions |

## Which cipher to use

Use **`Cipher\Crypto`** unless you have a specific reason not to. It delegates key generation,
encryption and authentication to `defuse/php-encryption`, a library built and reviewed for exactly
this purpose.

```bash
composer require defuse/php-encryption
```

```php
use Joomla\Crypt\Cipher\Crypto;
use Joomla\Crypt\Crypt;

$cipher = new Crypto();

// Generate a key once and store the ASCII form somewhere safe.
$key = $cipher->generateKey();
$secret = $key->getPrivate();          // save this

$crypt = new Crypt($cipher, $key);

$ciphertext = $crypt->encrypt('some secret value');
$plaintext  = $crypt->decrypt($ciphertext);
```

To use a stored key later, rebuild the `Key` object with the same type:

```php
use Joomla\Crypt\Key;

$key   = new Key('crypto', $secret, '');
$crypt = new Crypt(new Crypto(), $key);
```

`Crypto::generateKey()` currently puts the raw key bytes into the key object's *public* field. That
field is meaningless for a symmetric algorithm, so treat `getPublic()` on a `crypto` key as secret
material and never log, transmit or store it.

## Handling failures

Everything throws a typed exception implementing `CryptExceptionInterface`:

```php
use Joomla\Crypt\Exception\DecryptionException;
use Joomla\Crypt\Exception\InvalidKeyTypeException;

try {
    $plaintext = $crypt->decrypt($ciphertext);
} catch (DecryptionException $e) {
    // Wrong key, or the ciphertext was tampered with.
} catch (InvalidKeyTypeException $e) {
    // The Key does not belong to this cipher.
}
```

| Exception | Raised when |
|---|---|
| `EncryptionException` | Encryption failed |
| `DecryptionException` | Decryption failed or the ciphertext was modified |
| `InvalidKeyException` | A key could not be generated |
| `InvalidKeyTypeException` | The key type does not match the cipher |
| `UnsupportedCipherException` | The cipher is not supported in this environment (see below) |

Check support before choosing a cipher:

```php
if (!Crypto::isSupported()) {
    // fall back, or fail loudly
}
```

Since 4.1 `encrypt()`, `decrypt()` and `generateKey()` of every cipher throw
`UnsupportedCipherException` when `isSupported()` is `false`, instead of failing with a PHP error:

| Cipher | `isSupported()` is `true` when |
|---|---|
| `Crypto` | `defuse/php-encryption` is installed and its runtime self-test passes |
| `Sodium` | the `sodium_*` functions exist (ext-sodium, or `paragonie/sodium_compat`) |
| `OpenSSL` | ext-openssl is loaded |

This includes `new Crypt()` without a cipher, which falls back to `Crypto` and generates a key: without
`defuse/php-encryption` it throws `UnsupportedCipherException`.

## Random bytes

```php
Crypt::genRandomBytes(32);   // binary string, from random_bytes()
```

The result is **binary**. Run it through `bin2hex()` or `base64_encode()` before putting it in a
URL, a database column or a header.

## The Sodium cipher

`Cipher\Sodium` uses `sodium_crypto_box` and needs a nonce set before use:

```php
use Joomla\Crypt\Cipher\Sodium;

$cipher = new Sodium();
$key    = $cipher->generateKey();

$nonce = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);   // 24 bytes
$cipher->setNonce($nonce);

$ciphertext = $cipher->encrypt('message', $key);
```

Two things the package does not do for you, and both are essential:

* **Generate the nonce.** There is no helper; you must produce 24 random bytes yourself.
* **Vary it per message.** The nonce is stored on the cipher instance and reused for every
  `encrypt()` call on it. Reusing a nonce with the same key breaks XSalsa20-Poly1305 completely —
  it exposes the XOR of the plaintexts and undermines the authenticator. Create a fresh nonce for
  each message and store it alongside the ciphertext:

```php
$nonce = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);
$cipher->setNonce($nonce);
$stored = base64_encode($nonce) . ':' . base64_encode($cipher->encrypt($message, $key));
```

## The OpenSSL cipher

> **Do not use `Cipher\OpenSSL` for new work.** Its initialisation vector is fixed at construction
> and reused for every message, it applies no authentication to the ciphertext, and
> `generateKey()` uses the supplied passphrase directly as the raw key with no derivation. A fixed
> IV means identical plaintexts produce identical ciphertexts, and in a stream mode it means key
> stream reuse; the missing authentication means a modified ciphertext decrypts without complaint.
> Use `Cipher\Crypto` instead.

If you are stuck with it, one more detail matters. The option is called `passphrase` and the docs
describe it as a passphrase file, but the value is never read as a file — it is handed to
`openssl_encrypt()` as the key material verbatim:

```php
$key = $cipher->generateKey(['passphrase' => '/path/to/secret.dat']);
// the key is the string '/path/to/secret.dat', not the contents of that file
```

Combined with the cipher method's key length — `aes-128-cbc` consumes the first **16 bytes** and
ignores the rest — two "different" passphrase files in the same directory produce the *same*
encryption key, because their paths share that prefix:

```php
$a = $cipher->generateKey(['passphrase' => '/var/www/keys/tenant-a.dat']);
$b = $cipher->generateKey(['passphrase' => '/var/www/keys/tenant-b.dat']);
// aes-128-cbc sees '/var/www/keys/t' for both - the same key
```

If you must keep this cipher, pass the secret itself rather than a path, make sure it is at least
as long as the method's key size, and generate it with `random_bytes()`.

## Not part of this package

* No password hashing — that lives in `joomla/authentication` (`Password\BCryptHandler` and the
  Argon2 handlers).
* No key derivation (`sodium_crypto_pwhash`, PBKDF2, HKDF).
* No constant-time comparison helper — use `hash_equals()` directly.
* No signatures (`sodium_crypto_sign_*`), no AEAD cipher, no ciphertext envelope carrying the
  cipher identifier, IV/nonce and key id, and therefore no key rotation support.
