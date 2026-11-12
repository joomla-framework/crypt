# The Crypt Package [![Build Status](https://github.com/joomla-framework/crypt/actions/workflows/ci.yml/badge.svg?branch=4.x-dev)](https://github.com/joomla-framework/crypt)

[![Latest Stable Version](https://poser.pugx.org/joomla/crypt/v/stable)](https://packagist.org/packages/joomla/crypt)
[![Total Downloads](https://poser.pugx.org/joomla/crypt/downloads)](https://packagist.org/packages/joomla/crypt)
[![Latest Unstable Version](https://poser.pugx.org/joomla/crypt/v/unstable)](https://packagist.org/packages/joomla/crypt)
[![License](https://poser.pugx.org/joomla/crypt/license)](https://packagist.org/packages/joomla/crypt)

The Crypt package provides symmetric encryption behind a common cipher interface, a key object and a set of typed
exceptions. It does not hash passwords; use `joomla/authentication` or PHP's `password_hash()` for that.

## Classes

| Class | Purpose |
|---|---|
| `Joomla\Crypt\Crypt` | Pairs a cipher with a key and exposes `encrypt()`, `decrypt()` and `generateKey()` |
| `Joomla\Crypt\CipherInterface` | The cipher contract |
| `Joomla\Crypt\Cipher\Crypto` | Wrapper around `defuse/php-encryption` — **the recommended cipher** |
| `Joomla\Crypt\Cipher\Sodium` | libsodium `crypto_box` |
| `Joomla\Crypt\Cipher\OpenSSL` | ext-openssl — not recommended, see below |
| `Joomla\Crypt\Key` | Holds the key type and the private and public key material |
| `Joomla\Crypt\Exception\*` | `CryptExceptionInterface` and the concrete exceptions |

## Usage

`Cipher\Crypto` needs `defuse/php-encryption`, which is only a suggested dependency:

```sh
composer require defuse/php-encryption
```

```php
use Joomla\Crypt\Cipher\Crypto;
use Joomla\Crypt\Crypt;
use Joomla\Crypt\Key;

$cipher = new Crypto();

// Generate a key once and keep its private part in your secret storage
$key    = $cipher->generateKey();
$secret = $key->getPrivate();

// Later: rebuild the key and always pass both the cipher and the key
$crypt = new Crypt($cipher, new Key('crypto', $secret, ''));

$ciphertext = $crypt->encrypt('some secret value');
$plaintext  = $crypt->decrypt($ciphertext);
```

## Security notes

* Use `Cipher\Crypto` unless you have a specific reason not to. It authenticates the ciphertext and
  uses a random IV for every message.
* `Cipher\OpenSSL` reuses the initialisation vector passed to its constructor for every message,
  does not authenticate the ciphertext and uses the passphrase as the raw key. Do not use it for new work.
* `Cipher\Sodium` must never encrypt two messages with the same key and nonce. Read the
  documentation on nonce handling before using it.
* Never log, transmit or serialize a `Key`; keep the private key in your secret storage.

See the [documentation](docs/index.md) for details, and the update guides in `docs/` when upgrading
between major versions.

# Installation via Composer

Add `"joomla/crypt": "~4.0" to the require block in your composer.json and then run `composer install`.

```json
{
	"require": {
		"joomla/crypt": "~4.0"
	}
}
```

Alternatively, you can simply run the following from the command line:

```sh
composer require joomla/crypt "~4.0"
```

If you want to include the test sources, use

```sh
composer require --prefer-source joomla/crypt "~4.0"
```
