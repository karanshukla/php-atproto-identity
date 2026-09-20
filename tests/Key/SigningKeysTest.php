<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Tests\Key;

use KaranShukla\PhpAtprotoIdentity\IdentityException;
use KaranShukla\PhpAtprotoIdentity\Key\SigningKeys;
use KaranShukla\PhpAtprotoIdentity\Tests\Stub\TestKey;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class SigningKeysTest extends TestCase
{
    private const string DID = 'did:plc:requester';

    private const string OTHER_DID = 'did:plc:somebodyelse';

    public function testReadsTheAtprotoKeyADocumentPublishes(): void
    {
        $testKey = TestKey::secp256k1();

        $keys = SigningKeys::atproto($testKey->didDocument(self::DID));

        self::assertCount(1, $keys);
        self::assertEquals($testKey->verificationKey(), $keys[0]);
    }

    /** DID Core lets a method id be written relative to the document. */
    public function testAcceptsAMethodIdWrittenAsABareFragment(): void
    {
        $testKey = TestKey::secp256k1();

        $keys = SigningKeys::atproto(self::document([
            ['id' => '#atproto', 'publicKeyMultibase' => $testKey->multibase],
        ]));

        self::assertCount(1, $keys);
    }

    /**
     * The check this class exists for. `str_ends_with($id, '#atproto')` is
     * the obvious thing to write and it accepts this.
     */
    public function testIgnoresAnAtprotoMethodBelongingToAnotherDid(): void
    {
        $keys = SigningKeys::atproto(self::document([
            [
                'id' => self::OTHER_DID . '#atproto',
                'controller' => self::OTHER_DID,
                'publicKeyMultibase' => TestKey::secp256k1()->multibase,
            ],
        ]));

        self::assertSame([], $keys);
    }

    /** A method id can be the subject's while the controller is not. */
    public function testIgnoresAMethodControlledBySomebodyElse(): void
    {
        $keys = SigningKeys::atproto(self::document([
            [
                'id' => self::DID . '#atproto',
                'controller' => self::OTHER_DID,
                'publicKeyMultibase' => TestKey::secp256k1()->multibase,
            ],
        ]));

        self::assertSame([], $keys);
    }

    /**
     * A did:plc document publishes a rotation key too, and it signs
     * operations on the identity rather than anything in the repo.
     */
    public function testIgnoresAMethodThatIsNotTheAtprotoOne(): void
    {
        $keys = SigningKeys::atproto(self::document([
            [
                'id' => self::DID . '#rotation',
                'controller' => self::DID,
                'publicKeyMultibase' => TestKey::secp256k1()->multibase,
            ],
        ]));

        self::assertSame([], $keys);
    }

    /**
     * During a rotation the key that verifies a given signature may not be
     * the one listed first, so all of them come back in order.
     */
    public function testReturnsEveryAtprotoKeyInTheOrderTheyArePublished(): void
    {
        $first = TestKey::secp256k1();
        $second = TestKey::p256();

        $keys = SigningKeys::atproto(self::document([
            ['id' => self::DID . '#atproto', 'publicKeyMultibase' => $first->multibase],
            ['id' => self::DID . '#atproto', 'publicKeyMultibase' => $second->multibase],
        ]));

        self::assertCount(2, $keys);
        self::assertEquals($first->verificationKey(), $keys[0]);
        self::assertEquals($second->verificationKey(), $keys[1]);
    }

    /**
     * A key type this package cannot read does not cost the caller one it
     * can, which is the whole point of not failing the batch.
     */
    public function testSkipsAnUnreadableKeyBesideAReadableOne(): void
    {
        $testKey = TestKey::secp256k1();

        $keys = SigningKeys::atproto(self::document([
            // Ed25519, a real key type but not one ATProto signs repos with.
            ['id' => self::DID . '#atproto', 'publicKeyMultibase' => 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'],
            ['id' => self::DID . '#atproto', 'publicKeyMultibase' => $testKey->multibase],
        ]));

        self::assertCount(1, $keys);
        self::assertEquals($testKey->verificationKey(), $keys[0]);
    }

    /** With nothing readable left, silence would be the dangerous answer. */
    public function testThrowsWhenEveryAtprotoKeyIsUnreadable(): void
    {
        $this->expectException(IdentityException::class);
        $this->expectExceptionMessage('No usable ATProto signing key');

        SigningKeys::atproto(self::document([
            ['id' => self::DID . '#atproto', 'publicKeyMultibase' => 'not-a-multibase-string'],
        ]));
    }

    public function testThrowsWhenAnAtprotoMethodHasNoKeyOnIt(): void
    {
        $this->expectException(IdentityException::class);
        $this->expectExceptionMessage('no publicKeyMultibase');

        SigningKeys::atproto(self::document([
            ['id' => self::DID . '#atproto', 'type' => 'Multikey'],
        ]));
    }

    /**
     * Empty rather than an exception: a caller loops over the result and
     * rejects by never finding a key that verifies.
     */
    public function testReturnsNothingWhenTheDocumentPublishesNoAtprotoKey(): void
    {
        self::assertSame([], SigningKeys::atproto(self::document([])));
        self::assertSame([], SigningKeys::atproto(['id' => self::DID]));
    }

    /** DID Core lets an entry refer to a method defined elsewhere. */
    public function testPassesOverAnEntryThatIsAReferenceRatherThanAMethod(): void
    {
        $keys = SigningKeys::atproto(self::document([
            self::DID . '#atproto',
            ['id' => self::DID . '#atproto', 'publicKeyMultibase' => TestKey::secp256k1()->multibase],
        ]));

        self::assertCount(1, $keys);
    }

    public function testRefusesADocumentWithNoSubjectToAttributeKeysTo(): void
    {
        $this->expectException(IdentityException::class);
        $this->expectExceptionMessage('no id');

        SigningKeys::atproto(['verificationMethod' => []]);
    }

    /**
     * @param list<mixed> $methods
     *
     * @return array<string, mixed>
     */
    private static function document(array $methods): array
    {
        return ['id' => self::DID, 'verificationMethod' => $methods];
    }
}
