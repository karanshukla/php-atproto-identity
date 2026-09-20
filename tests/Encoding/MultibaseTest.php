<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Tests\Encoding;

use KaranShukla\PhpAtprotoIdentity\Encoding\Multibase;
use KaranShukla\PhpAtprotoIdentity\IdentityException;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class MultibaseTest extends TestCase
{
    public function testStripsThePrefixAndDecodesWhatIsBehindIt(): void
    {
        self::assertSame('yes mani !', Multibase::decode('z7paNL19xttacUY'));
    }

    public function testRejectsABaseOtherThanBase58btc(): void
    {
        $this->expectException(IdentityException::class);

        // The same bytes in base64url (multibase `u`), which is a real
        // encoding but not the one ATProto publishes keys in.
        Multibase::decode('ueWVzIG1hbmkgIQ');
    }

    public function testRejectsAStringWithNoPrefixAtAll(): void
    {
        $this->expectException(IdentityException::class);

        Multibase::decode('7paNL19xttacUY');
    }

    /**
     * base58 decoding is quadratic, and without ext-gmp it is quadratic in
     * PHP: 20,000 characters is five seconds of CPU. The string arrives
     * inside a DID document, so on a did:web its length belongs to whoever
     * the DID names, and the only thing standing between them and that five
     * seconds is this bound.
     */
    public function testRefusesAStringTooLongToBeAKey(): void
    {
        $this->expectException(IdentityException::class);
        $this->expectExceptionMessage('longer than');

        Multibase::decode('z' . str_repeat('z', Multibase::MAX_LENGTH));
    }

    /** A real key is 49 characters, so the bound has room to spare. */
    public function testAcceptsAStringRightUpToTheBound(): void
    {
        // `1` is base58btc's zero digit, so this is a run of zero bytes.
        $decoded = Multibase::decode('z' . str_repeat('1', Multibase::MAX_LENGTH - 1));

        self::assertSame(str_repeat("\x00", Multibase::MAX_LENGTH - 1), $decoded);
    }
}
