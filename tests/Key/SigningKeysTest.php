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

    private const string ED25519_KEY = 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

    /** secp256k1's prefix over x = 5, which has no square root on the curve. */
    private const string OFF_CURVE_KEY = 'zQ3shMQnkqiyfujhRPGFFqSEeD2yV9kUcmyBiu2fT2BXfFPMN';

    public function testReadsTheAtprotoKeyADocumentPublishes(): void
    {
        $testKey = TestKey::secp256k1();

        $keys = SigningKeys::atproto($testKey->didDocument(self::DID));

        self::assertCount(1, $keys);
        self::assertEquals($testKey->verificationKey(), $keys[0]);
    }

    public function testAcceptsAMethodIdWrittenAsABareFragment(): void
    {
        $testKey = TestKey::secp256k1();

        $keys = SigningKeys::atproto(self::document([
            ['id' => '#atproto', 'publicKeyMultibase' => $testKey->multibase],
        ]));

        self::assertCount(1, $keys);
    }

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

    public function testSkipsAnUnreadableKeyBesideAReadableOne(): void
    {
        $testKey = TestKey::secp256k1();

        $keys = SigningKeys::atproto(self::document([
            ['id' => self::DID . '#atproto', 'publicKeyMultibase' => self::ED25519_KEY],
            ['id' => self::DID . '#atproto', 'publicKeyMultibase' => $testKey->multibase],
        ]));

        self::assertCount(1, $keys);
        self::assertEquals($testKey->verificationKey(), $keys[0]);
    }

    /**
     * Well formed and the right length, so only the curve can refuse it. A
     * caller looping over the result must not meet it as a throw from pem()
     * on the way to the key that works.
     */
    public function testSkipsAKeyThatIsNotOnItsCurveBesideOneThatIs(): void
    {
        $testKey = TestKey::secp256k1();

        $keys = SigningKeys::atproto(self::document([
            ['id' => self::DID . '#atproto', 'publicKeyMultibase' => self::OFF_CURVE_KEY],
            ['id' => self::DID . '#atproto', 'publicKeyMultibase' => $testKey->multibase],
        ]));

        self::assertCount(1, $keys);
        self::assertEquals($testKey->verificationKey(), $keys[0]);
    }

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

    public function testReturnsNothingWhenTheDocumentPublishesNoAtprotoKey(): void
    {
        self::assertSame([], SigningKeys::atproto(self::document([])));
        self::assertSame([], SigningKeys::atproto(['id' => self::DID]));
    }

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
