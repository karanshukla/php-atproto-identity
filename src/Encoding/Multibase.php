<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Encoding;

use KaranShukla\PhpAtprotoIdentity\IdentityException;

/**
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\Encoding\MultibaseTest
 */
final class Multibase
{
    /**
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Encoding\MultibaseTest::testRefusesAStringTooLongToBeAKey()
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Encoding\MultibaseTest::testAcceptsAStringRightUpToTheBound()
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
