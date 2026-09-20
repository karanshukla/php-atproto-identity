<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Key;

use KaranShukla\PhpAtprotoIdentity\IdentityException;

/**
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\Key\SigningKeysTest
 */
final class SigningKeys
{
    public const string ATPROTO_FRAGMENT = '#atproto';

    /**
     * @param array<string, mixed> $document as returned by
     *                                       {@see \KaranShukla\PhpAtprotoIdentity\Resolution\DidDocumentResolver::resolve()}
     *
     * @return list<VerificationKey> every `#atproto` key the document
     *                               publishes, in the order it publishes
     *                               them; empty if it publishes none
     *
     * @throws IdentityException if the document publishes `#atproto` keys and
     *                           not one of them could be read
     *
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Key\SigningKeysTest::testReturnsEveryAtprotoKeyInTheOrderTheyArePublished()
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Key\SigningKeysTest::testReturnsNothingWhenTheDocumentPublishesNoAtprotoKey()
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Key\SigningKeysTest::testSkipsAnUnreadableKeyBesideAReadableOne()
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Key\SigningKeysTest::testSkipsAKeyThatIsNotOnItsCurveBesideOneThatIs()
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
     * DID Core lets a method id be written relative to the document, so a
     * bare `#atproto` is the same claim as the subject's own.
     *
     * @param array<array-key, mixed> $method
     *
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Key\SigningKeysTest::testIgnoresAnAtprotoMethodBelongingToAnotherDid()
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Key\SigningKeysTest::testIgnoresAMethodControlledBySomebodyElse()
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Key\SigningKeysTest::testAcceptsAMethodIdWrittenAsABareFragment()
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
     * elsewhere rather than the method itself.
     *
     * @param array<string, mixed> $document
     *
     * @return list<array<array-key, mixed>>
     *
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Key\SigningKeysTest::testPassesOverAnEntryThatIsAReferenceRatherThanAMethod()
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
