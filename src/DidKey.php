<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity;

/**
 * Decodes the `publicKeyMultibase` form ATProto DID documents publish.
 *
 * The string is base58btc (multibase `z`) over a multicodec-prefixed
 * compressed EC point.
 *
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\DidKeyTest
 */
final class DidKey
{
    private const string PREFIX_SECP256K1 = "\xe7\x01";

    private const string PREFIX_P256 = "\x80\x24";

    public static function fromMultibase(string $multibase): VerificationKey
    {
        if (!str_starts_with($multibase, 'z')) {
            throw new IdentityException('publicKeyMultibase is not base58btc (expected a `z` prefix)');
        }

        $bytes = Base58::decode(substr($multibase, 1));
        $prefix = substr($bytes, 0, 2);
        $point = substr($bytes, 2);

        $curve = match ($prefix) {
            self::PREFIX_SECP256K1 => VerificationKey::CURVE_SECP256K1,
            self::PREFIX_P256 => VerificationKey::CURVE_P256,
            default => throw new IdentityException(
                \sprintf('Unsupported multicodec prefix 0x%s', bin2hex($prefix)),
            ),
        };

        if (\strlen($point) !== 33) {
            throw new IdentityException('Expected a 33-byte compressed point');
        }

        return new VerificationKey($curve, $point);
    }

    public static function fromDidKey(string $didKey): VerificationKey
    {
        return self::fromMultibase(str_starts_with($didKey, 'did:key:') ? substr($didKey, 8) : $didKey);
    }
}
