# Updating from v4 to v5

Release 5.0.0 removes API that was deprecated in 4.x and adds native types to the public API. Each
breaking change has its own section below.

<!-- Section: Crypt requires a cipher and a key -->


## Native parameter and return types

The cipher API and `Crypt` now declare native types:

| Method | v4 | v5 |
|---|---|---|
| `CipherInterface::encrypt()` | `encrypt($data, Key $key)` | `encrypt(string $data, Key $key): string` |
| `CipherInterface::decrypt()` | `decrypt($data, Key $key)` | `decrypt(string $data, Key $key): string` |
| `CipherInterface::generateKey()` | `generateKey(array $options = [])` | `generateKey(array $options = []): Key` |
| `Crypt::encrypt()` | `encrypt($data)` | `encrypt(string $data): string` |
| `Crypt::decrypt()` | `decrypt($data)` | `decrypt(string $data): string` |
| `Crypt::generateKey()` | `generateKey(array $options = [])` | `generateKey(array $options = []): Key` |
| `Crypt::setKey()` | `setKey(Key $key)` | `setKey(Key $key): static` |
| `Crypt::genRandomBytes()` | `genRandomBytes($length = 16)` | `genRandomBytes(int $length = 16): string` |

`Cipher\Crypto`, `Cipher\OpenSSL` and `Cipher\Sodium` implement the new interface signatures.

**What to change:**

* Your own `CipherInterface` implementations must declare the same parameter and return types.
* Subclasses of `Crypt` or of the bundled ciphers that override these methods must add the return
  types.
* `null` is no longer accepted as data: `encrypt(null)` throws a `TypeError` instead of being
  treated as an empty string. Without `declare(strict_types=1)`, integers and floats are still
  converted to strings.


<!-- Section: Sodium::setNonce() removed -->


## Dependency changes

| Package | v4 (4.0.0) | v5 (5.0.0) |
|---|---|---|
| `php` | `^8.3.0` | `^8.3.0` |
