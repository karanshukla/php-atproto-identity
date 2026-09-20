<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Encoding;

use InvalidArgumentException;
use KaranShukla\PhpAtprotoIdentity\IdentityException;
use Tuupola\Base58 as Codec;

/**
 * base58btc, the encoding multibase uses behind the `z` prefix.
 *
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\Encoding\Base58Test::testDecodesTheMultibaseSpecVectors()
 */
final class Base58
{
    public static function decode(string $input): string
    {
        try {
            return new Codec(['characters' => Codec::BITCOIN])->decode($input);
        } catch (InvalidArgumentException $e) {
            throw new IdentityException("Invalid base58btc string: {$e->getMessage()}", previous: $e);
        }
    }
}
