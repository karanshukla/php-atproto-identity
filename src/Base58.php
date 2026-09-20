<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity;

use Brick\Math\BigInteger;
use Brick\Math\Exception\MathException;

/**
 * base58btc, the encoding multibase uses behind the `z` prefix.
 *
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\Base58Test::testDecodesTheMultibaseSpecVectors()
 */
final class Base58
{
    private const string ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

    private const string ZERO_DIGIT = '1';

    public static function decode(string $input): string
    {
        if ($input === '') {
            return '';
        }

        try {
            $number = BigInteger::fromArbitraryBase($input, self::ALPHABET);
        } catch (MathException $e) {
            throw new IdentityException("Invalid base58btc string: {$e->getMessage()}", previous: $e);
        }

        return self::leadingZeroBytes($input) . ($number->isZero() ? '' : $number->toBytes(false));
    }

    /**
     * Leading zero bytes survive the round trip only because base58btc spells
     * each one as a separate `1`; the integer itself cannot carry them.
     */
    private static function leadingZeroBytes(string $input): string
    {
        $zeroes = 0;

        while ($zeroes < \strlen($input) && $input[$zeroes] === self::ZERO_DIGIT) {
            $zeroes++;
        }

        return str_repeat("\x00", $zeroes);
    }
}
