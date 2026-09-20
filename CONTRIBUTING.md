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

## Layout

```
src/
├── IdentityException.php   thrown by everything, so it sits above the rest
├── Encoding/               base58, and the multibase envelope over it
├── Key/                    did:key decoding and the EC key it yields
└── Resolution/             DID method to URL, and fetching what is there
    └── Cache/              the document cache and its PSR-6 adapter
```

Dependencies run one way: `Key` uses `Encoding`, `Resolution` uses `Cache`,
and everything uses `IdentityException`. `Multicodec` sits under `Key` rather
than `Encoding` because its prefixes name curves — it is key knowledge written
as an encoding, and filing it under `Encoding` would point that arrow
backwards. `tests/` mirrors the tree.

## Before opening a PR

`composer qa` has to be clean. CI runs the same three tools on PHP 8.4 and
8.5, plus `composer audit`, and `main` requires all of it to pass.

- **php-cs-fixer** — `composer phpcsfixer` reports; `composer phpcsfix`
  applies.
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

## Cutting a release

Push a tag. `.github/workflows/release.yml` re-runs the full CI gate against
that commit, checks the tag is actually on `main`, and publishes the GitHub
release.

```bash
git switch main && git pull
git tag -a v0.2.0 -m "v0.2.0"
git push origin v0.2.0
```

`composer.json` carries no `version` field on purpose. Packagist reads the tag,
so the tag is the only place a version number exists and there is nothing to
keep in sync. A tag with a suffix (`v0.2.0-beta.1`) is published as a
prerelease, which is how Composer already reads that string.

The notes are generated from the PRs merged since the previous tag, grouped by
label. `.github/release.yml` holds the label to heading mapping:

| Label | Heading |
|---|---|
| `breaking` | Breaking changes |
| `security` | Security |
| `enhancement` | Features |
| `bug` | Fixes |
| `documentation`, `ci` | Documentation and tooling |
| `dependencies` | Dependencies |
| (none) | Other changes |

So the changelog is only as good as the labels. Label the PR when you open it,
not at release time. `changelog-ignore` drops a PR from the notes entirely.

The one thing this does not do is write prose. Generated notes are a list of PR
titles, which is enough for a patch release and not enough for a breaking one.
Edit the release body by hand when the change needs explaining.

## Scope

This package resolves DIDs and reads the keys they publish. That's it.

JWT verification, session handling, lexicon types and XRPC all live a layer
up — see [libphpsky](https://github.com/aazsamir/libphpsky). A change that
needs this package to know what a service auth token is probably belongs
there instead.

New DID methods and new key types are in scope. Both are small, table-driven
additions: a URL rule in `DidDocumentUrl`, or a multicodec prefix in
`Multicodec` plus an entry in `VerificationKey::CURVES`. A new curve needs both
SPKI headers, and the comment above that constant explains how they are
derived.

## AI Disclosure

You are not required to disclose AI coding tool usage for code generation or code review. However, fully AI generated PRs will not be accepted unless there is a language barrier. You can have AI help you write the PR of course, but you should understand your PR and the code well enough to defend the changes made. 