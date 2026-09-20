# Resolving a DID you do not trust

A DID that arrives from outside (a token's issuer, a record's subject)
decides which URL this library fetches, so four things hold by default,
without any configuration:

| | |
|---|---|
| **The URL cannot be bent** | A `did:web` identifier is held to a domain name with an optional port, and a `did:plc` identifier cannot escape the directory it is appended to. Percent-encoding is decoded before that check, not after, so `did:web:trusted.test%40evil.test` is refused rather than fetched from `evil.test`. |
| **The host has to be a public domain** | At least one dot, and a last label that begins with a letter. That refuses `did:web:localhost`, `did:web:127.0.0.1` and a bare container or service name. A punycode label passes, so IDN domains resolve. This one is a default rather than a prohibition: see below for how to ask for a host it refuses. |
| **The document has to claim the DID** | A document whose `id` is not the DID it was fetched for is refused, so a `did:web` host cannot publish a document impersonating somebody else's DID. |
| **Untrusted input is bounded** | A response body past 256 KiB is refused rather than parsed, and a `publicKeyMultibase` longer than any key could be is refused rather than decoded. |

## Naming the hosts you expect

If the DIDs you resolve come from a known set, name it:

```php
$resolver = new HttpDidDocumentResolver(
    httpClient: $client,
    requestFactory: $factory,
    allowedHosts: ['feed.example.com', 'pds.example.com:8443'],
);
```

Nothing off that list is fetched, and the request is refused before it is
sent. An entry without a port means port 443, so listing a host does not also
hand out whatever else that machine is running; write the port when you mean
a different one. The PLC directory you configured is always reachable without
being listed, so `did:plc` keeps working.

## Reaching a local host

Naming a list is also how you reach a host the public-domain rule would
otherwise refuse, which is what you want when the thing you are resolving is
a PDS on your own machine:

```php
$resolver = new HttpDidDocumentResolver(
    httpClient: $client,
    requestFactory: $factory,
    plcDirectory: 'http://localhost:2582',
    allowedHosts: ['localhost:3000'],
);

$resolver->resolve('did:web:localhost%3A3000');
```

The rule is a default because this package takes whatever PSR-18 client you
hand it, and a stock one will dial anything. `@atproto/identity` does not need
the rule, because it ships an SSRF-protected fetch of its own; it goes the
other way and special-cases `localhost` down to plain HTTP. Here you just have
to say you meant it.

## What is left to the HTTP client

What none of this can bound is where a request *ends up*. A name with a dot in
it can still resolve to an internal address, whether by DNS rebinding, a
split-horizon resolver or a search domain, and an allowed host is free to
answer with a 302 to a private one. Egress is the HTTP client's job, and the
client is yours: for DIDs you have no reason to trust, hand this resolver a
client with an egress proxy or a blocked private-address range rather than
your default one, and turn redirect-following off.
