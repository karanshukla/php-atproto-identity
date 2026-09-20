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
    /**
     * base58 decoding is quadratic in the length of its input, and the only
     * implementation that is not slow about it needs ext-gmp, which this
     * package does not require and a stock php image does not have. A
     * multibase string arrives inside a DID document, which for did:web is
     * written by whoever the DID names, so its length is theirs to choose and
     * a long one is CPU spent on their say-so.
     *
     * A multicodec-prefixed compressed point is 35 bytes, which is 48
     * base58btc characters and the prefix. This leaves several times that in
     * headroom and still bounds the work at a few microseconds.
     *
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Encoding\MultibaseTest::testRefusesAStringTooLongToBeAKey()
     */
    public const int MAX_LENGTH = 256;

    private const string BASE58BTC = 'z';

    public static function decode(string $multibase): string
    {
        if (!str_starts_with($multibase, self::BASE58BTC)) {
            throw new IdentityException('publicKeyMultibase is not base58btc (expected a `z` prefix)');
        }

        if (\strlen($multibase) > self::MAX_LENGTH) {
            throw new IdentityException(
                \sprintf('publicKeyMultibase is longer than %d characters, which no key is', self::MAX_LENGTH),
            );
        }

        return Base58::decode(substr($multibase, 1));
    }
}
