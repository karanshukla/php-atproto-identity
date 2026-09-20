<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Key;

use KaranShukla\PhpAtprotoIdentity\IdentityException;

/**
 * The signing keys a DID document publishes for ATProto, picked out of it.
 *
 * Reading a key out of a document looks like two lines of array access, which
 * is why everyone writes those two lines and why they are usually wrong. The
 * selection is the security-relevant part: a document is a list of keys and
 * picking the wrong one is picking a key its owner did not intend for this,
 * or one somebody else published.
 *
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\Key\SigningKeysTest
 */
final class SigningKeys
{
    /**
     * The fragment ATProto names its repo signing key with. A document may
     * publish other methods -- a PLC rotation key, a key for some other
     * protocol -- and none of them verifies a repo commit or a service auth
     * token.
     */
    public const string ATPROTO_FRAGMENT = '#atproto';

    /**
     * Every `#atproto` key the document publishes, in the order it publishes
     * them.
     *
     * A list rather than one key, because a document may publish more than
     * one and during a rotation the one that verifies a given signature may
     * not be the one listed first. Try each until one verifies; that none of
     * them does is a rejection, not an error.
     *
     * Empty means the document publishes no ATProto signing key at all, which
     * a caller looping over the result rejects by doing nothing.
     *
     * @param array<string, mixed> $document as returned by
     *                                       {@see \KaranShukla\PhpAtprotoIdentity\Resolution\DidDocumentResolver::resolve()}
     *
     * @return list<VerificationKey>
     *
     * @throws IdentityException if the document publishes `#atproto` keys and
     *                           not one of them could be read
     */
    public static function atproto(array $document): array
    {
        $subject = $document['id'] ?? null;

        if (!\is_string($subject)) {
            throw new IdentityException('DID document has no id, so nothing in it can be attributed');
        }

        $keys = [];
        $failures = [];

        foreach (self::verificationMethods($document) as $method) {
            if (!self::isAtprotoMethodOf($subject, $method)) {
                continue;
            }

            $multibase = $method['publicKeyMultibase'] ?? null;

            if (!\is_string($multibase)) {
                $failures[] = 'a method with no publicKeyMultibase';

                continue;
            }

            try {
                $keys[] = DidKey::fromMultibase($multibase);
            } catch (IdentityException $e) {
                // Skipped rather than fatal: a document mid-rotation may
                // publish a key this package cannot read alongside one it
                // can, and the readable one is the whole point.
                $failures[] = $e->getMessage();
            }
        }

        if ($keys === [] && $failures !== []) {
            throw new IdentityException(
                'No usable ATProto signing key in the document: ' . implode('; ', $failures),
            );
        }

        return $keys;
    }

    /**
     * The one check worth having a class for.
     *
     * A method's `id` says which DID published it, and a document is free to
     * list a method whose id belongs to somebody else. Matching on the
     * fragment alone -- `str_ends_with($id, '#atproto')`, which is the
     * obvious thing to write -- accepts `did:plc:somebodyelse#atproto` out of
     * a document you resolved for someone, so the subject has to be checked
     * too. DID Core lets the id be written relative to the document, so a
     * bare `#atproto` is the same claim and is accepted as one.
     *
     * `controller` is checked for the same reason when it is present: it
     * names who the key belongs to, and only the subject's own keys are
     * theirs to sign with.
     *
     * @param array<array-key, mixed> $method
     *
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Key\SigningKeysTest::testIgnoresAnAtprotoMethodBelongingToAnotherDid()
     */
    private static function isAtprotoMethodOf(string $subject, array $method): bool
    {
        $id = $method['id'] ?? null;

        if (!\is_string($id)) {
            return false;
        }

        if ($id !== self::ATPROTO_FRAGMENT && $id !== $subject . self::ATPROTO_FRAGMENT) {
            return false;
        }

        $controller = $method['controller'] ?? null;

        return $controller === null || $controller === $subject;
    }

    /**
     * DID Core lets an entry be a string referring to a method defined
     * elsewhere rather than the method itself. There is nothing to read in
     * one, so it is passed over.
     *
     * @param array<string, mixed> $document
     *
     * @return list<array<array-key, mixed>>
     */
    private static function verificationMethods(array $document): array
    {
        $methods = $document['verificationMethod'] ?? null;

        if (!\is_array($methods)) {
            return [];
        }

        return array_values(array_filter($methods, \is_array(...)));
    }
}
