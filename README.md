# php-atproto-identity

Resolve an ATProto DID to its document, and turn the signing key that document
publishes into something OpenSSL can verify with.

That is the whole package. It is the layer `@atproto/identity` occupies in the
TypeScript world, and nothing framework-specific lives in it: the HTTP client,
the cache and the PSR interfaces are all yours to supply.

```bash
composer require karanshukla/php-atproto-identity
```

Requires PHP 8.4 and `ext-openssl`, which ships enabled in virtually every PHP
build. Nothing else: no bignum extension, no configuration.

## What it does

| | |
|---|---|
| **DID methods** | `did:plc` (via a PLC directory) and `did:web` (via `.well-known/did.json`) |
| **Key types** | `secp256k1` (ES256K) and P-256 (ES256), the two ATProto signs repos with |
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

A cached document is served for an hour without touching the network, and a
stale one for up to a day if the fetch fails. Both bounds are constructor
arguments. `forceRefresh: true` skips the cache, which is what you want after a
signature fails to verify and you suspect a rotated key. Without a cache
argument, nothing is cached at all.

## Resolving a DID you do not trust

A DID that arrives from outside (a token's issuer, a record's subject) decides
which URL this library fetches. By default the URL cannot be bent to another
host or path, the host has to be a public domain, the document has to claim the
DID it was fetched for, and the body is capped at 256 KiB.

If the DIDs you resolve come from a known set, name it. Nothing off the list is
fetched, and listing a host is also how you reach one the public-domain rule
refuses, like `localhost:3000`:

```php
$resolver = new HttpDidDocumentResolver(
    httpClient: $client,
    requestFactory: $factory,
    allowedHosts: ['feed.example.com', 'pds.example.com:8443'],
);
```

What this cannot bound is where a request *ends up*: DNS and redirects belong
to the HTTP client, and the client is yours.
[docs/untrusted-dids.md](docs/untrusted-dids.md) has the rules in full and what
to ask of the client.

## Reading a published key

```php
use KaranShukla\PhpAtprotoIdentity\Key\SigningKeys;

$keys = SigningKeys::atproto($document);   // every #atproto key, in order
$key = $keys[0];

$key->curve;        // 'secp256k1'
$key->algorithm();  // 'ES256K', the JWS alg a token signed by it must declare
$key->pem();        // a PEM any JWT library or openssl_verify() will accept
$key->der();        // the same key as a DER SubjectPublicKeyInfo
```

Only the `#atproto` keys that belong to the document's own subject come back,
and a key that is not on its curve is never one of them. It is a list because
a document may publish more than one, and during a rotation the one that
verifies a given signature may not be listed first.

If you already have a key in hand, `DidKey::fromMultibase()` takes the
`publicKeyMultibase` string and `DidKey::fromDidKey()` takes the
`did:key:z...` form. [docs/keys.md](docs/keys.md) covers what is checked and
how a compressed point becomes a PEM.

## Verifying a service auth token

The package stops short of JWT verification on purpose, so you can bring
whatever JWT library you already use. The shape is:

```php
$document = $resolver->resolve($issuerDid);

foreach (SigningKeys::atproto($document) as $key) {
    // ... hand $key->pem() and $key->algorithm() to your verifier
}
```

Try every key it hands back rather than stopping at the first, for the
rotation reason above. If none of them verifies, resolve again with
`forceRefresh: true` before rejecting the token. That is the one failure a
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
