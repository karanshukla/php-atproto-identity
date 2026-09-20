# php-atproto-identity

Resolve an ATProto DID to its document, and turn the signing key that document
publishes into something OpenSSL can verify with.

That is the whole package. It is the layer `@atproto/identity` occupies in the
TypeScript world, and nothing framework-specific lives in it — the HTTP client,
the cache and the PSR interfaces are all yours to supply.

```bash
composer require karanshukla/php-atproto-identity
```

Requires PHP 8.4 and `ext-openssl`, which ships enabled in virtually every PHP
build. Nothing else — no bignum extension, no configuration.

## What it does

| | |
|---|---|
| **DID methods** | `did:plc` (via a PLC directory) and `did:web` (via `.well-known/did.json`) |
| **Key types** | `secp256k1` (ES256K) and P-256 (ES256) — the two ATProto signs repos with |
| **Caching** | any PSR-6 pool, or your own `DidDocumentCache` |
| **HTTP** | any PSR-18 client and PSR-17 request factory |

## Resolving a DID

```php
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\HttpFactory;
use KaranShukla\PhpAtprotoIdentity\Resolution\Cache\Psr6DidDocumentCache;
use KaranShukla\PhpAtprotoIdentity\Resolution\HttpDidDocumentResolver;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;

$resolver = new HttpDidDocumentResolver(
    httpClient: new Client(),
    requestFactory: new HttpFactory(),
    cache: new Psr6DidDocumentCache(new FilesystemAdapter()),
);

$document = $resolver->resolve('did:plc:z72i7hdynmk6r22z27h6tvur');
```

The resolver serves a cached document for an hour without touching the
network, refetches it after that, and — if the directory is unreachable — keeps
serving a stale one for up to a day rather than failing. Those two bounds match
`@atproto/identity`'s `MemoryCache`, and both are constructor arguments. Pass
`forceRefresh: true` to skip the cache, which is what you want after a
signature fails to verify and you suspect a rotated key.

Without a cache argument, nothing is cached at all.

## Resolving a DID you do not trust

A DID that arrives from outside — a token's issuer, a record's subject —
decides which URL this library fetches. A `did:web` identifier is held to a
hostname with an optional port, so it cannot bend that URL somewhere else,
and a `did:plc` identifier cannot escape the directory it is appended to. A
hostname is still enough to aim a request at anything that resolves, though,
including addresses inside your own network.

If the DIDs you resolve come from a known set, name it:

```php
$resolver = new HttpDidDocumentResolver(
    httpClient: $client,
    requestFactory: $factory,
    allowedHosts: ['feed.example.com', 'pds.example.com'],
);
```

Nothing off that list is fetched, and the request is refused before it is
sent. The PLC directory you configured is always reachable without being
listed, so `did:plc` keeps working. An empty list — the default — allows any
host.

What an allowlist cannot bound is where a request *ends up*. Egress is the
HTTP client's job, and the client is yours: for DIDs you have no reason to
trust, hand this resolver a client with an egress proxy or a blocked
private-address range rather than your default one, and turn
redirect-following off — an allowed host is otherwise free to answer with a
302 to a private one.

## Reading a published key

```php
use KaranShukla\PhpAtprotoIdentity\Key\DidKey;

$key = DidKey::fromMultibase($document['verificationMethod'][0]['publicKeyMultibase']);

$key->curve;        // 'secp256k1'
$key->algorithm();  // 'ES256K' — the JWS alg a token signed by it must declare
$key->pem();        // a PEM any JWT library or openssl_verify() will accept
$key->der();        // the same key as a DER SubjectPublicKeyInfo
```

`DidKey::fromDidKey()` takes the `did:key:z...` form as well.

ATProto publishes keys as a compressed point — an X coordinate and one bit of
Y — so `pem()` has to recover Y by taking a modular square root in the curve's
field. RFC 5480 allows a `SubjectPublicKeyInfo` to carry a compressed point, so
the key is handed to OpenSSL exactly as published and comes back decompressed:
the square root happens in C and the on-curve check comes free. A build whose
OpenSSL declines falls back to the same arithmetic in PHP. Either way, a point
that is not on the curve is rejected.

## Verifying a service auth token

The package stops short of JWT verification on purpose, so you can bring
whatever JWT library you already use. The shape is:

```php
$document = $resolver->resolve($issuerDid);

foreach ($document['verificationMethod'] ?? [] as $method) {
    if (!str_ends_with($method['id'] ?? '', '#atproto')) {
        continue;
    }

    $key = DidKey::fromMultibase($method['publicKeyMultibase']);

    // ... hand $key->pem() and $key->algorithm() to your verifier
}
```

Try every `#atproto` method rather than just the first: a DID document may
publish more than one, and during a key rotation the one you want may not be
the one listed first. If verification still fails, resolve again with
`forceRefresh: true` before rejecting the token — that is the one failure a
fresher document can fix.

[libphpsky](https://github.com/aazsamir/libphpsky) wires this up into a full
`ServiceAuthVerifier` with audience, expiry and `lxm` checks.

## Errors

Everything throws `IdentityException`, which extends `RuntimeException`.

## Development

```bash
composer install
composer qa        # php-cs-fixer, phpstan (level max), phpunit
```

The test suite generates its own keys with OpenSSL and asserts that the PEM
this library derives from the compressed point is byte-for-byte what OpenSSL
exports for the same key. No fixtures, no network.

## License

MIT
