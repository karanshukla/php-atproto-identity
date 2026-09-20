<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Key;

use KaranShukla\PhpAtprotoIdentity\IdentityException;

/**
 * The multicodec prefix a published key carries, which names the curve the
 * bytes behind it belong to.
 *
 * Both prefixes ATProto signs with introduce a compressed EC point, so the
 * length behind them is fixed and checked here.
 *
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\Key\MulticodecTest
 */
final class Multicodec
{
    private const string PREFIX_SECP256K1 = "\xe7\x01";

    private const string PREFIX_P256 = "\x80\x24";

    private const int PREFIX_BYTES = 2;

    private const int COMPRESSED_POINT_BYTES = 33;

    /**
     * Splits a prefixed key into the curve its prefix names and the point
     * behind it.
     *
     * @return array{string, string} one of the VerificationKey::CURVE_*
     *                               constants, and a 33-byte compressed point
     */
    public static function compressedPoint(string $bytes): array
    {
        $prefix = substr($bytes, 0, self::PREFIX_BYTES);
        $point = substr($bytes, self::PREFIX_BYTES);

        $curve = match ($prefix) {
            self::PREFIX_SECP256K1 => VerificationKey::CURVE_SECP256K1,
            self::PREFIX_P256 => VerificationKey::CURVE_P256,
            default => throw new IdentityException(
                \sprintf('Unsupported multicodec prefix 0x%s', bin2hex($prefix)),
            ),
        };

        if (\strlen($point) !== self::COMPRESSED_POINT_BYTES) {
            throw new IdentityException(
                \sprintf('Expected a %d-byte compressed point', self::COMPRESSED_POINT_BYTES),
            );
        }

        return [$curve, $point];
    }
}
