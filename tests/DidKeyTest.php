<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Tests;

use Brick\Math\BigInteger;
use KaranShukla\PhpAtprotoIdentity\DidKey;
use KaranShukla\PhpAtprotoIdentity\IdentityException;
use KaranShukla\PhpAtprotoIdentity\Tests\Stub\TestKey;
use KaranShukla\PhpAtprotoIdentity\VerificationKey;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class DidKeyTest extends TestCase
{
    public function testDerivesAUsableSecp256k1KeyFromItsMultibaseForm(): void
    {
        $testKey = TestKey::secp256k1();
        $decoded = DidKey::fromMultibase($testKey->multibase);

        self::assertSame(VerificationKey::CURVE_SECP256K1, $decoded->curve);
        self::assertSame('ES256K', $decoded->algorithm());
        self::assertTrue(self::verifies($testKey, $decoded));
    }

    public function testDerivesAUsableP256KeyFromItsMultibaseForm(): void
    {
        $testKey = TestKey::p256();
        $decoded = DidKey::fromMultibase($testKey->multibase);

        self::assertSame(VerificationKey::CURVE_P256, $decoded->curve);
        self::assertSame('ES256', $decoded->algorithm());
        self::assertTrue(self::verifies($testKey, $decoded));
    }

    public function testAcceptsTheDidKeyForm(): void
    {
        $multibase = TestKey::secp256k1()->multibase;

        self::assertEquals(
            DidKey::fromMultibase($multibase),
            DidKey::fromDidKey('did:key:' . $multibase),
        );
    }

    public function testRejectsAMultibaseThatIsNotBase58btc(): void
    {
        $this->expectException(IdentityException::class);

        DidKey::fromMultibase('mAQIDBA');
    }

    public function testRejectsAKeyTypeAtprotoDoesNotSignWith(): void
    {
        $this->expectException(IdentityException::class);

        // Ed25519 (multicodec 0xed 0x01): a real key type, but not one used
        // for ATProto repo signatures.
        DidKey::fromMultibase('z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK');
    }

    public function testRejectsAMulticodecPrefixWithNoPointBehindIt(): void
    {
        $this->expectException(IdentityException::class);

        // secp256k1's prefix over a point three bytes short.
        DidKey::fromMultibase('z' . self::base58btc("\xe7\x01\x02" . str_repeat("\x11", 29)));
    }

    /**
     * The one claim that matters: a key read out of a DID document verifies
     * what the matching private half signed.
     */
    private static function verifies(TestKey $testKey, VerificationKey $decoded): bool
    {
        $message = 'a message only the private half could have signed';
        $public = openssl_pkey_get_public($decoded->pem());

        self::assertNotFalse($public);

        return openssl_verify($message, $testKey->sign($message), $public, \OPENSSL_ALGO_SHA256) === 1;
    }

    /**
     * @param non-empty-string $bytes
     */
    private static function base58btc(string $bytes): string
    {
        return BigInteger::fromBytes($bytes, false)
            ->toArbitraryBase('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz');
    }
}
