<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Tests\Key;

use KaranShukla\PhpAtprotoIdentity\IdentityException;
use KaranShukla\PhpAtprotoIdentity\Key\VerificationKey;
use KaranShukla\PhpAtprotoIdentity\Tests\Stub\TestKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

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
     * The PHP fallback only runs on a build whose OpenSSL refuses a compressed
     * SubjectPublicKeyInfo, which is none of the ones this is tested on. Left
     * to normal use it would be dead code, so it is called directly and held
     * to the same answer OpenSSL gives.
     */
    #[DataProvider('provideBothCurvesCases')]
    public function testTheFallbackAgreesWithOpenssl(TestKey $testKey): void
    {
        $key = $testKey->verificationKey();
        $point = $key->compressedPoint;

        $fallback = new ReflectionMethod($key, 'viaModularSquareRoot')
            ->invoke(null, $key->curve, \ord($point[0]), substr($point, 1));

        $viaOpenssl = new ReflectionMethod($key, 'viaOpenssl')
            ->invoke(null, $key->curve, $point);

        self::assertSame($viaOpenssl, $fallback);
        // ...and therefore that OpenSSL did get used for the real answer.
        self::assertSame($testKey->publicPem, $key->pem());
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
     * A point OpenSSL declines because it is invalid, rather than because it
     * is compressed, still has to be rejected once it reaches the fallback.
     */
    public function testAnInvalidPointIsRejectedByTheFallbackToo(): void
    {
        $key = new VerificationKey(
            VerificationKey::CURVE_SECP256K1,
            "\x02" . str_pad(pack('N', 5), 32, "\x00", \STR_PAD_LEFT),
        );

        $this->expectException(IdentityException::class);
        $this->expectExceptionMessage('does not lie on secp256k1');

        new ReflectionMethod($key, 'viaModularSquareRoot')
            ->invoke(null, $key->curve, 0x02, substr($key->compressedPoint, 1));
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

    /**
     * OpenSSL's error queue is global to the process and appended to, so a
     * key this package refuses puts entries on it that the caller did not
     * cause and cannot explain. Left there, the next openssl_error_string()
     * anywhere in the process reports them.
     *
     * @param non-empty-string $compressedPoint
     */
    #[DataProvider('provideLeavesNoOpensslErrorsBehindWhenItRejectsAKeyCases')]
    public function testLeavesNoOpensslErrorsBehindWhenItRejectsAKey(string $compressedPoint): void
    {
        self::drainOpensslErrors();

        try {
            new VerificationKey(VerificationKey::CURVE_SECP256K1, $compressedPoint)->pem();
        } catch (IdentityException) {
            // The rejection is the point; what it leaves behind is the test.
        }

        self::assertSame(0, self::drainOpensslErrors());
    }

    /**
     * @return iterable<string, array{non-empty-string}>
     */
    public static function provideLeavesNoOpensslErrorsBehindWhenItRejectsAKeyCases(): iterable
    {
        yield 'an x that is not on the curve' => [
            "\x02" . str_pad(pack('N', 5), 32, "\x00", \STR_PAD_LEFT),
        ];

        yield 'an x outside the field' => [
            "\x02" . str_repeat("\xff", 32),
        ];
    }

    /** The same promise on the path where nothing went wrong. */
    public function testLeavesNoOpensslErrorsBehindWhenItReadsAKey(): void
    {
        self::drainOpensslErrors();

        TestKey::secp256k1()->verificationKey()->pem();

        self::assertSame(0, self::drainOpensslErrors());
    }

    /**
     * @return int how many entries were on the queue, which is the only way
     *             to ask: reading it consumes it
     */
    private static function drainOpensslErrors(): int
    {
        $count = 0;

        while (openssl_error_string() !== false) {
            $count++;
        }

        return $count;
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
