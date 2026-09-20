# Contributing

## Getting set up

```bash
composer install
composer qa        # php-cs-fixer, phpstan (level max), phpunit
```

`ext-openssl` is required. `ext-gmp` and `ext-bcmath` are not, and the
`No gmp or bcmath` CI job exists to keep it that way. Before putting a
`brick/math` operation anywhere it runs per request, check what it costs with
neither extension loaded — a 256-bit `modPow` is about 1.5ms on GMP or BCMath
and about 1.5 *seconds* on the pure-PHP calculator. That gap is the whole
reason `VerificationKey` asks OpenSSL first.

## Before opening a PR

`composer qa` has to be clean. CI runs the same three tools on PHP 8.4 and
8.5, plus `composer audit`, and `main` requires all of it to pass.

- **php-cs-fixer** — run `composer phpcsfixer -- --dry-run=false` to apply
  fixes rather than just report them.
- **phpstan** — level max, over `src` and `tests` alike. Don't silence a
  finding with a baseline entry, an `@phpstan-ignore` comment, an `assert()`
  or a cast; narrow the type properly or fix the bug it found.
- **phpunit** — no network, no fixtures. Tests generate their own keys with
  OpenSSL.

## What a good test looks like here

The suite leans on differential testing rather than golden files: OpenSSL
generates a key, and the assertion is that this library derives byte-for-byte
the same thing from the compressed point OpenSSL published. `TestKey` also
encodes base58 itself instead of calling `Base58`, so a round trip runs
through two independently written implementations. Prefer that shape over
checked-in fixtures, which only prove the code still does what it did.

Name tests as sentences about behaviour (`testFallsBackToAStaleDocumentWhenTheFetchFails`)
rather than after the method under test.

## Scope

This package resolves DIDs and reads the keys they publish. That's it.

JWT verification, session handling, lexicon types and XRPC all live a layer
up — see [libphpsky](https://github.com/aazsamir/libphpsky). A change that
needs this package to know what a service auth token is probably belongs
there instead.

New DID methods and new key types are in scope. Both are small, table-driven
additions: a URL rule in `HttpDidDocumentResolver`, or a multicodec prefix in
`DidKey` plus an entry in `VerificationKey::CURVES`. A new curve needs both
SPKI headers, and the comment above that constant explains how they are
derived.
