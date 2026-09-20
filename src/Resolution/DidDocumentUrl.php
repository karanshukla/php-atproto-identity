<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Resolution;

use KaranShukla\PhpAtprotoIdentity\IdentityException;

/**
 * Where a DID publishes its document, per the rules its method lays down.
 *
 * A DID method is in practice two rules: how to turn an identifier into a
 * URL, and what the document there has to look like. This is the first of
 * them, and the only part that differs between did:plc and did:web.
 *
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\DidDocumentUrlTest
 */
final class DidDocumentUrl
{
    private const string PLC_PREFIX = 'did:plc:';

    private const string WEB_PREFIX = 'did:web:';

    /**
     * A hostname with an optional port, which is all a did:web identifier
     * decodes to. Deliberately narrow: whatever this lets through is a
     * character the caller gets to place in a URL this process then fetches.
     */
    private const string HOST = '/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*(?::\d{1,5})?$/i';

    /**
     * A did:plc identifier is base32, but the format has changed once
     * already, so this rules out only what would change the shape of the URL
     * it is appended to, rather than pinning the alphabet and the length.
     */
    private const string PLC_IDENTIFIER = '/^[a-zA-Z0-9._-]+$/';

    public static function for(string $did, string $plcDirectory): string
    {
        if (str_starts_with($did, self::PLC_PREFIX)) {
            self::check($did, substr($did, \strlen(self::PLC_PREFIX)), self::PLC_IDENTIFIER);

            return rtrim($plcDirectory, '/') . '/' . $did;
        }

        if (str_starts_with($did, self::WEB_PREFIX)) {
            $identifier = substr($did, \strlen(self::WEB_PREFIX));

            // A did:web addresses a path by writing its separators as colons.
            // ATProto only ever publishes at the domain root, and a path form
            // is likelier a mangled identifier than a document worth fetching.
            if (str_contains($identifier, ':')) {
                throw new IdentityException('did:web with a path is not supported');
            }

            // Checked after decoding rather than before, because the decoded
            // string is what ends up in the URL: `%40` decodes to an `@`, and
            // did:web:trusted.test%40evil.test would otherwise build a URL
            // that reads as trusted.test and is fetched from evil.test. `%2F`
            // and `%3F` are the same trick against the path and the query.
            $host = urldecode($identifier);

            self::check($did, $host, self::HOST);

            return 'https://' . $host . '/.well-known/did.json';
        }

        throw new IdentityException("Unsupported DID method in {$did}");
    }

    /**
     * A DID reaches this class straight off the wire -- out of a token's
     * issuer field, say -- and every character of it lands in a URL this
     * process then fetches. So an identifier is held to its method's alphabet
     * rather than trusted to stay inside the shape of the URL.
     */
    private static function check(string $did, string $identifier, string $pattern): void
    {
        if (preg_match($pattern, $identifier) !== 1) {
            throw new IdentityException("Malformed DID identifier in {$did}");
        }
    }
}
