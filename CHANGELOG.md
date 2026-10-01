# Changelog

All notable changes to this package are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- `SigningKeys::atproto()` reads at most `MAX_ATPROTO_METHODS` (8) `#atproto` methods. A 256 KiB document padded with a few thousand of them took several seconds of OpenSSL parsing on every call.

## [0.2.0] - 2026-10-01

### Added

- `SigningKeys::atproto()` picks the `#atproto` verification keys out of a resolved DID document. It checks that each method belongs to the document's subject, returns every match in order so a key rotation does not hide the one that verifies, and skips a key it cannot read rather than losing a readable one beside it.

### Changed

- Resolving a host outside the public domain (`localhost`, private addresses) is now a default the resolver applies, not a rule baked into the DID grammar. An `allowedHosts` entry overrides it, and the configured PLC directory is exempt.
- `VerificationKey` checks its point when constructed, so an off-curve key fails at construction rather than later in `pem()`.

### Security

- A `did:web` document whose `id` is not the DID it was fetched for is refused, so a hostile host can no longer serve a document claiming to be another DID.
- An unsupported DID method, a malformed identifier or a host the caller refused is no longer served from the stale cache; these now fail ahead of the cache read, `forceRefresh` included.
- A DID with a trailing newline (`did:plc:abc\n`) is refused.
- An invalid curve point is rejected through OpenSSL before the pure-PHP square root, which took about two seconds with neither `gmp` nor `bcmath` loaded.

### Fixed

- OpenSSL errors no longer leak into the caller's error queue after a rejected key.

[Unreleased]: https://github.com/karanshukla/php-atproto-identity/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/karanshukla/php-atproto-identity/compare/v0.1.1...v0.2.0
