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
}
