<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Tests\Encoding;

use KaranShukla\PhpAtprotoIdentity\Encoding\Multibase;
use KaranShukla\PhpAtprotoIdentity\IdentityException;
use KaranShukla\PhpAtprotoIdentity\Tests\Stub\TestKey;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class MultibaseTest extends TestCase
{
    private const string BASE58BTC_ZERO_DIGIT = '1';

    private const int HEADROOM_OVER_A_REAL_KEY = 8;

    public function testStripsThePrefixAndDecodesWhatIsBehindIt(): void
    {
        self::assertSame('yes mani !', Multibase::decode('z7paNL19xttacUY'));
    }

    public function testRejectsABaseOtherThanBase58btc(): void
    {
        $sameBytesInBase64url = 'ueWVzIG1hbmkgIQ';

        $this->expectException(IdentityException::class);

        Multibase::decode($sameBytesInBase64url);
    }

    public function testRejectsAStringWithNoPrefixAtAll(): void
    {
        $this->expectException(IdentityException::class);

        Multibase::decode('7paNL19xttacUY');
    }

    public function testRefusesAStringTooLongToBeAKey(): void
    {
        $this->expectException(IdentityException::class);
        $this->expectExceptionMessage('longer than');

        Multibase::decode('z' . str_repeat('z', Multibase::MAX_LENGTH));
    }

    public function testAcceptsAStringRightUpToTheBound(): void
    {
        $zeroDigits = str_repeat(self::BASE58BTC_ZERO_DIGIT, Multibase::MAX_LENGTH - 1);

        self::assertSame(
            str_repeat("\x00", Multibase::MAX_LENGTH - 1),
            Multibase::decode('z' . $zeroDigits),
        );
    }

    public function testKeepsTheBoundWithinHeadroomOfARealKey(): void
    {
        $realKey = TestKey::secp256k1()->multibase;

        self::assertLessThanOrEqual(
            \strlen($realKey) * self::HEADROOM_OVER_A_REAL_KEY,
            Multibase::MAX_LENGTH,
            'base58 decoding is quadratic without ext-gmp, so a bound far above a real key is not a bound',
        );
    }
}
