<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Resolution;

use KaranShukla\PhpAtprotoIdentity\IdentityException;

/**
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\DidDocumentUrlTest
 */
final class DidDocumentUrl
{
    private const string PLC_PREFIX = 'did:plc:';

    private const string WEB_PREFIX = 'did:web:';

    /**
     * @see \KaranShukla\PhpAtprotoIdentity\Resolution\HttpDidDocumentResolver::checkHostIsAllowed()
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\DidDocumentUrlTest::testLeavesTheQuestionOfAPrivateHostToTheResolver()
     */
    private const string HOST = '/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*(?::\d{1,5})?$/i';

    /**
     * The did:plc format has changed once already, so this rules out only
     * what would change the shape of the URL, not the alphabet or the length.
     */
    private const string PLC_IDENTIFIER = '/^[a-zA-Z0-9._-]+$/';

    private const int MAX_IDENTIFIER_LENGTH = 260;

    public static function for(string $did, string $plcDirectory): string
    {
        if (str_starts_with($did, self::PLC_PREFIX)) {
            self::check($did, substr($did, \strlen(self::PLC_PREFIX)), self::PLC_IDENTIFIER);

            return rtrim($plcDirectory, '/') . '/' . $did;
        }

        if (str_starts_with($did, self::WEB_PREFIX)) {
            $identifier = substr($did, \strlen(self::WEB_PREFIX));

            // A did:web writes path separators as colons.
            if (str_contains($identifier, ':')) {
                throw new IdentityException('did:web with a path is not supported');
            }

            // Checked after the decode, because the decoded string is what
            // lands in the URL.
            $host = urldecode($identifier);

            self::check($did, $host, self::HOST);

            return 'https://' . $host . '/.well-known/did.json';
        }

        throw new IdentityException("Unsupported DID method in {$did}");
    }

    private static function check(string $did, string $identifier, string $pattern): void
    {
        if (\strlen($identifier) > self::MAX_IDENTIFIER_LENGTH || preg_match($pattern, $identifier) !== 1) {
            throw new IdentityException("Malformed DID identifier in {$did}");
        }
    }
}
