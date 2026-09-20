<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Tests\Key;

use KaranShukla\PhpAtprotoIdentity\IdentityException;
use KaranShukla\PhpAtprotoIdentity\Key\Multicodec;
use KaranShukla\PhpAtprotoIdentity\Key\VerificationKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class MulticodecTest extends TestCase
{
    #[DataProvider('provideNamesTheCurveItsPrefixStandsForCases')]
    public function testNamesTheCurveItsPrefixStandsFor(string $prefix, string $expected): void
    {
        $point = str_repeat("\x11", 33);

        self::assertSame([$expected, $point], Multicodec::compressedPoint($prefix . $point));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideNamesTheCurveItsPrefixStandsForCases(): iterable
    {
        yield 'secp256k1' => ["\xe7\x01", VerificationKey::CURVE_SECP256K1];
        yield 'p256' => ["\x80\x24", VerificationKey::CURVE_P256];
    }

    public function testRejectsAKeyTypeAtprotoDoesNotSignWith(): void
    {
        $this->expectException(IdentityException::class);

        // Ed25519 (multicodec 0xed 0x01): a real key type, but not one used
        // for ATProto repo signatures.
        Multicodec::compressedPoint("\xed\x01" . str_repeat("\x11", 32));
    }

    public function testRejectsAPointThatIsNotACompressedOne(): void
    {
        $this->expectException(IdentityException::class);

        // An uncompressed secp256k1 point, which is 65 bytes rather than 33.
        Multicodec::compressedPoint("\xe7\x01\x04" . str_repeat("\x11", 64));
    }

    public function testRejectsAPrefixWithNothingBehindIt(): void
    {
        $this->expectException(IdentityException::class);

        Multicodec::compressedPoint("\xe7\x01");
    }
}
