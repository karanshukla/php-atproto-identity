<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Encoding;

use KaranShukla\PhpAtprotoIdentity\IdentityException;

/**
 * The multibase envelope: a leading character naming the base the rest of the
 * string is written in.
 *
 * Only base58btc (`z`) is understood, because that is the one ATProto
 * publishes keys in.
 *
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\Encoding\MultibaseTest
 */
final class Multibase
{
    private const string BASE58BTC = 'z';

    public static function decode(string $multibase): string
    {
        if (!str_starts_with($multibase, self::BASE58BTC)) {
            throw new IdentityException('publicKeyMultibase is not base58btc (expected a `z` prefix)');
        }

        return Base58::decode(substr($multibase, 1));
    }
}
