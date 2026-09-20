<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Tests;

use KaranShukla\PhpAtprotoIdentity\Base58;
use KaranShukla\PhpAtprotoIdentity\IdentityException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class Base58Test extends TestCase
{
    #[DataProvider('provideDecodesTheMultibaseSpecVectorsCases')]
    public function testDecodesTheMultibaseSpecVectors(string $encoded, string $expected): void
    {
        self::assertSame($expected, Base58::decode($encoded));
    }

    /**
     * The vectors the multibase spec publishes for base58btc, which is what
     * the `z` prefix on a publicKeyMultibase means.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function provideDecodesTheMultibaseSpecVectorsCases(): iterable
    {
        yield 'empty' => ['', ''];
        yield 'single character' => ['Z', ' '];
        yield 'a zero on its own' => ['1', "\x00"];
        yield 'nothing but zeroes' => ['11', "\x00\x00"];
        yield 'yes mani !' => ['7paNL19xttacUY', 'yes mani !'];
        yield 'one leading zero byte' => ['17paNL19xttacUY', "\x00yes mani !"];
        yield 'two leading zero bytes' => ['117paNL19xttacUY', "\x00\x00yes mani !"];
    }

    public function testRejectsACharacterOutsideTheAlphabet(): void
    {
        $this->expectException(IdentityException::class);

        // 0 and O are left out of base58 precisely because they are confusable.
        Base58::decode('0O');
    }
}
