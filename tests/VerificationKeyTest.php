<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Tests;

use KaranShukla\PhpAtprotoIdentity\IdentityException;
use KaranShukla\PhpAtprotoIdentity\Tests\Stub\TestKey;
use KaranShukla\PhpAtprotoIdentity\VerificationKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class VerificationKeyTest extends TestCase
{
    /**
     * The load-bearing test for the decompression: OpenSSL generated the key,
     * so OpenSSL's own export of it is the answer, byte for byte.
     */
    #[DataProvider('provideBothCurvesCases')]
    public function testDerivesTheSameKeyOpensslWould(TestKey $testKey): void
    {
        self::assertSame($testKey->publicPem, $testKey->verificationKey()->pem());
    }

    #[DataProvider('provideBothCurvesCases')]
    public function testProducesAPemOpensslCanRead(TestKey $testKey): void
    {
        $public = openssl_pkey_get_public($testKey->verificationKey()->pem());

        self::assertNotFalse($public);
        self::assertSame(\OPENSSL_KEYTYPE_EC, openssl_pkey_get_details($public)['type'] ?? null);
    }

    /**
     * @return iterable<string, array{TestKey}>
     */
    public static function provideBothCurvesCases(): iterable
    {
        yield 'secp256k1' => [TestKey::secp256k1()];
        yield 'p256' => [TestKey::p256()];
    }

    /**
     * Both roots of the same X are on the curve, so nothing downstream would
     * complain if the parity bit were ignored -- only this will.
     */
    public function testTheParityPrefixSelectsBetweenTheTwoRoots(): void
    {
        $point = TestKey::secp256k1()->verificationKey()->compressedPoint;
        $flipped = ($point[0] === "\x02" ? "\x03" : "\x02") . substr($point, 1);

        $pem = new VerificationKey(VerificationKey::CURVE_SECP256K1, $point)->pem();
        $otherPem = new VerificationKey(VerificationKey::CURVE_SECP256K1, $flipped)->pem();

        self::assertNotSame($pem, $otherPem);
        self::assertNotFalse(openssl_pkey_get_public($otherPem));
    }

    public function testRejectsACurveItDoesNotKnow(): void
    {
        $this->expectException(IdentityException::class);

        new VerificationKey('curve25519', "\x02" . str_repeat("\x11", 32));
    }

    public function testRejectsAPointOfTheWrongLength(): void
    {
        $this->expectException(IdentityException::class);

        new VerificationKey(VerificationKey::CURVE_SECP256K1, "\x02" . str_repeat("\x00", 16))->pem();
    }

    public function testRejectsAPointWithoutAParityPrefix(): void
    {
        $this->expectException(IdentityException::class);

        // 0x04 is the uncompressed marker, not a parity bit.
        new VerificationKey(VerificationKey::CURVE_SECP256K1, "\x04" . str_repeat("\x00", 32))->pem();
    }

    /** x = 5 has no square root on secp256k1. */
    public function testRejectsAnXThatIsNotOnTheCurve(): void
    {
        $this->expectException(IdentityException::class);

        new VerificationKey(
            VerificationKey::CURVE_SECP256K1,
            "\x02" . str_pad(pack('N', 5), 32, "\x00", \STR_PAD_LEFT),
        )->pem();
    }

    /** X must be reduced mod p; the field prime itself is one past the end. */
    public function testRejectsAnXOutsideTheField(): void
    {
        $this->expectException(IdentityException::class);

        $p = hex2bin('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f');
        self::assertNotFalse($p);

        new VerificationKey(VerificationKey::CURVE_SECP256K1, "\x02" . $p)->pem();
    }
}
