<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity;

use Brick\Math\BigInteger;
use Brick\Math\Exception\MathException;

/**
 * An elliptic-curve public key recovered from a DID document, in a form
 * OpenSSL will accept.
 *
 * ATProto publishes signing keys as compressed points inside a multibase
 * string -- an X coordinate and one bit of Y -- while verifiers want a
 * PEM-encoded SubjectPublicKeyInfo over an uncompressed one. Recovering Y
 * means a modular square root in the curve's field; see
 * {@see self::uncompressed()} for where that happens and why there are two
 * ways of doing it.
 *
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\VerificationKeyTest
 */
final readonly class VerificationKey
{
    public const string CURVE_SECP256K1 = 'secp256k1';

    public const string CURVE_P256 = 'p256';

    /**
     * Per curve: the JWS algorithm a token signed by it declares, the field
     * prime and the two coefficients of `y^2 = x^3 + ax + b`, and the two
     * SubjectPublicKeyInfo headers that can precede its point.
     *
     * Each header is a constant because every field ahead of the point is one
     * -- `SEQUENCE { SEQUENCE { OID ecPublicKey, OID namedCurve },
     * BIT STRING }` -- and the two forms differ only in the lengths pinned by
     * the point that follows: 33 bytes compressed, 65 uncompressed. Both stop
     * at the BIT STRING's unused-bit count, so the point is appended as-is.
     */
    private const array CURVES = [
        self::CURVE_SECP256K1 => [
            'algorithm' => 'ES256K',
            'p' => 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
            'a' => '0',
            'b' => '7',
            // ... OID 1.2.840.10045.2.1 ecPublicKey, OID 1.3.132.0.10 secp256k1
            'compressed' => '3036301006072a8648ce3d020106052b8104000a032200',
            'uncompressed' => '3056301006072a8648ce3d020106052b8104000a034200',
        ],
        self::CURVE_P256 => [
            'algorithm' => 'ES256',
            'p' => 'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
            'a' => 'ffffffff00000001000000000000000000000000fffffffffffffffffffffffc',
            'b' => '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
            // ... OID 1.2.840.10045.2.1 ecPublicKey, OID 1.2.840.10045.3.1.7 prime256v1
            'compressed' => '3039301306072a8648ce3d020106082a8648ce3d030107032200',
            'uncompressed' => '3059301306072a8648ce3d020106082a8648ce3d030107034200',
        ],
    ];

    private const int COORDINATE_BYTES = 32;

    private const string UNCOMPRESSED_MARKER = "\x04";

    /**
     * @param string $curve one of the self::CURVE_* constants
     * @param string $compressedPoint 33 bytes: a 0x02/0x03 parity prefix and X
     */
    public function __construct(
        public string $curve,
        public string $compressedPoint,
    ) {
        if (!isset(self::CURVES[$this->curve])) {
            throw new IdentityException("Unsupported curve {$this->curve}");
        }
    }

    /**
     * The JWS algorithm identifier a token signed by this key must declare.
     */
    public function algorithm(): string
    {
        return self::CURVES[$this->curve]['algorithm'];
    }

    public function pem(): string
    {
        return self::wrap($this->der());
    }

    /**
     * The key as a DER-encoded SubjectPublicKeyInfo over an uncompressed
     * point, which is the form every EC verifier understands.
     *
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\VerificationKeyTest::testDerivesTheSameKeyOpensslWould()
     */
    public function der(): string
    {
        [$x, $y] = $this->uncompressed();

        return self::header($this->curve, 'uncompressed') . self::UNCOMPRESSED_MARKER . $x . $y;
    }

    /**
     * Recovers Y from X and the parity bit.
     *
     * Tried two ways, in order. RFC 5480 permits a SubjectPublicKeyInfo to
     * carry its point compressed, so the key can be handed to OpenSSL exactly
     * as published and read back decompressed -- the square root happens in C
     * and the on-curve check comes free. Every OpenSSL build tested does this,
     * but the RFC permits a reader not to, so a build that refuses falls
     * through to doing the same arithmetic in PHP.
     *
     * The order matters for more than tidiness: the PHP path costs about 1.5ms
     * with ext-gmp or ext-bcmath loaded and about 1.5 *seconds* with neither,
     * where brick/math drops to a pure-PHP calculator. Stock php:cli images
     * have neither.
     *
     * @return array{string, string} X and Y, each left-padded to 32 bytes
     */
    private function uncompressed(): array
    {
        $parityByte = $this->compressedPoint[0] ?? '';
        $xBytes = substr($this->compressedPoint, 1);

        if ($parityByte === '' || \strlen($xBytes) !== self::COORDINATE_BYTES) {
            throw new IdentityException('Compressed point must be 33 bytes');
        }

        $prefix = \ord($parityByte);

        if ($prefix !== 0x02 && $prefix !== 0x03) {
            throw new IdentityException(\sprintf('Unexpected point prefix 0x%02x', $prefix));
        }

        return self::viaOpenssl($this->curve, $this->compressedPoint)
            ?? self::viaModularSquareRoot($this->curve, $prefix, $xBytes);
    }

    /**
     * Null when this OpenSSL will not read the key, for either reason: the
     * build does not accept a compressed SubjectPublicKeyInfo, or the point
     * is not a valid one. Both fall through to
     * {@see self::viaModularSquareRoot()}, which distinguishes them -- an
     * invalid point fails its on-curve check there and is rejected.
     *
     * @return array{string, string}|null
     */
    private static function viaOpenssl(string $curve, string $compressedPoint): ?array
    {
        // Drain anything an earlier call left in OpenSSL's error queue, so it
        // cannot be mistaken for a failure of this one.
        while (openssl_error_string() !== false) {
            continue;
        }

        $public = openssl_pkey_get_public(
            self::wrap(self::header($curve, 'compressed') . $compressedPoint),
        );

        if ($public === false) {
            return null;
        }

        $details = openssl_pkey_get_details($public);
        $point = $details === false ? null : $details['ec'] ?? null;

        if (!\is_array($point)) {
            return null;
        }

        $x = $point['x'] ?? null;
        $y = $point['y'] ?? null;

        if (!\is_string($x) || !\is_string($y)) {
            return null;
        }

        return [self::coordinate($x), self::coordinate($y)];
    }

    /**
     * The same recovery done here, for a build whose OpenSSL would not.
     *
     * Both curves have p = 3 (mod 4), where a square root -- if one exists at
     * all -- is alpha^((p+1)/4). Squaring the result back is what proves X was
     * ever on the curve, and is therefore also the rejection path for a point
     * OpenSSL declined because it was invalid rather than because it was
     * compressed.
     *
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\VerificationKeyTest::testTheFallbackAgreesWithOpenssl()
     *
     * @param non-empty-string $xBytes
     *
     * @return array{string, string}
     */
    private static function viaModularSquareRoot(string $curve, int $prefix, string $xBytes): array
    {
        $params = self::CURVES[$curve];

        try {
            $p = BigInteger::fromBase($params['p'], 16);
            $x = BigInteger::fromBytes($xBytes, false);

            if ($x->isGreaterThanOrEqualTo($p)) {
                throw new IdentityException('X is not a member of the field');
            }

            $ySquared = $x->power(3)
                ->plus(BigInteger::fromBase($params['a'], 16)->multipliedBy($x))
                ->plus(BigInteger::fromBase($params['b'], 16))
                ->mod($p);

            $y = $ySquared->modPow($p->plus(1)->shiftedRight(2), $p);

            if (!$y->multipliedBy($y)->mod($p)->isEqualTo($ySquared)) {
                throw new IdentityException("X does not lie on {$curve}");
            }

            // Y and p - Y are the two roots; the prefix says which was meant.
            // Zero is its own negation, so an odd prefix cannot describe it.
            if ($y->isZero()) {
                if ($prefix === 0x03) {
                    throw new IdentityException('No odd Y exists for this X');
                }
            } elseif ($y->isOdd() !== ($prefix === 0x03)) {
                $y = $p->minus($y);
            }
        } catch (MathException $e) {
            throw new IdentityException("Could not read the published signing key: {$e->getMessage()}", previous: $e);
        }

        return [self::coordinate($x->toBytes(false)), self::coordinate($y->toBytes(false))];
    }

    /**
     * @param 'compressed'|'uncompressed' $form
     */
    private static function header(string $curve, string $form): string
    {
        $header = hex2bin(self::CURVES[$curve][$form]);

        if ($header === false) {
            throw new IdentityException("Malformed {$form} header for {$curve}");
        }

        return $header;
    }

    /**
     * Both sources emit a coordinate with its leading zero bytes stripped; the
     * encoding wants every one of them back.
     */
    private static function coordinate(string $value): string
    {
        return str_pad($value, self::COORDINATE_BYTES, "\x00", \STR_PAD_LEFT);
    }

    private static function wrap(string $der): string
    {
        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }
}
