# Updating from v3 to v4

Release 4.0.0 raises the PHP requirement. Nothing else changed in `src/`.

## At a glance

| | v3 (3.0.2) | v4 (4.0.0) |
|---|---|---|
| PHP | `^8.1.0` | `^8.3.0` |
| Public API | — | unchanged |

## Minimum supported PHP version raised

All Framework packages now require **PHP 8.3** or newer.

## No API changes

`git diff 3.0.2 HEAD -- src/` is empty. Every class is byte-for-byte identical to 3.0.2, so
upgrading is a matter of satisfying the PHP requirement.

## Dependency changes

| Package | v3 (3.0.2) | v4 (4.0.0) |
|---|---|---|
| `php` | `^8.1.0` | `^8.3.0` |

The optional packages in `suggest` are unchanged: `ext-openssl`, `ext-sodium`,
`defuse/php-encryption`, `paragonie/sodium_compat`.

## Worth doing while you are here

The upgrade itself is trivial, but if your code uses `Cipher\OpenSSL`, this is a good moment to
move to `Cipher\Crypto`. See [the overview](overview.md#the-openssl-cipher) for why.
