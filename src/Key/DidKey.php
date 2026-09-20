<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Key;

use KaranShukla\PhpAtprotoIdentity\Encoding\Multibase;

/**
 * Decodes the `publicKeyMultibase` form ATProto DID documents publish.
 *
 * The string is base58btc (multibase `z`) over a multicodec-prefixed
 * compressed EC point, so the two encodings come off in that order:
 * {@see Multibase} for the outer one, {@see Multicodec} for the inner.
 *
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\Key\DidKeyTest
 */
final class DidKey
{
    private const string DID_KEY_PREFIX = 'did:key:';

    public static function fromMultibase(string $multibase): VerificationKey
    {
        [$curve, $point] = Multicodec::compressedPoint(Multibase::decode($multibase));

        return new VerificationKey($curve, $point);
    }

    public static function fromDidKey(string $didKey): VerificationKey
    {
        return self::fromMultibase(
            str_starts_with($didKey, self::DID_KEY_PREFIX)
                ? substr($didKey, \strlen(self::DID_KEY_PREFIX))
                : $didKey,
        );
    }
}
