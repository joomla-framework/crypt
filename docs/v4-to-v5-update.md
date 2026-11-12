# Updating from v4 to v5

Release 5.0.0 removes API that was deprecated in 4.x and adds native types to the public API. Each
breaking change has its own section below.

<!-- Section: Crypt requires a cipher and a key -->


<!-- Section: native parameter and return types -->


## `Sodium::setNonce()` removed

`Cipher\Sodium::setNonce()`, deprecated in 4.1, is gone. Since 4.1 the cipher generates a random
nonce for every message and stores it in front of the ciphertext; a nonce set with `setNonce()` was
reused for every message, which is insecure with `crypto_box`.

**What to change:**

* Remove `setNonce()` calls. `encrypt()` and `decrypt()` need nothing but the key.
* Data encrypted with a fixed nonce (with `setNonce()`) cannot be decrypted by the 5.x cipher.
  Re-encrypt it while still on 4.x:

  ```php
  $legacy = new Sodium();
  $legacy->setNonce($storedNonce);

  $ciphertext = (new Sodium())->encrypt($legacy->decrypt($oldCiphertext, $key), $key);
  ```

  or decrypt it directly with `sodium_crypto_box_open($oldCiphertext, $storedNonce,
  sodium_crypto_box_keypair_from_secretkey_and_publickey($key->getPrivate(), $key->getPublic()))`.


## Dependency changes

| Package | v4 (4.0.0) | v5 (5.0.0) |
|---|---|---|
| `php` | `^8.3.0` | `^8.3.0` |
