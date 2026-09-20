<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Key;

use Brick\Math\BigInteger;
use Brick\Math\Exception\MathException;
use KaranShukla\PhpAtprotoIdentity\IdentityException;

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
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\Key\VerificationKeyTest
 */
final readonly class VerificationKey
{
    public const string CURVE_SECP256K1 = 'secp256k1';

    public const string CURVE_P256 = 'p256';

    /**
     * Per curve: the JWS algorithm a token signed by it declares, the field
     * prime and the two coefficients of `y^2 = x^3 + ax + b`, and the two
     * SubjectPublicKeyInfo headers that can precede its point. `g` is the
     * curve's generator, compressed: a point known to be valid, for
     * {@see self::opensslReadsCompressedKeys()} to ask OpenSSL about.
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
            'g' => '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            // ... OID 1.2.840.10045.2.1 ecPublicKey, OID 1.3.132.0.10 secp256k1
            'compressed' => '3036301006072a8648ce3d020106052b8104000a032200',
            'uncompressed' => '3056301006072a8648ce3d020106052b8104000a034200',
        ],
        self::CURVE_P256 => [
            'algorithm' => 'ES256',
            'p' => 'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
            'a' => 'ffffffff00000001000000000000000000000000fffffffffffffffffffffffc',
            'b' => '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
            'g' => '036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',
            // ... OID 1.2.840.10045.2.1 ecPublicKey, OID 1.2.840.10045.3.1.7 prime256v1
            'compressed' => '3039301306072a8648ce3d020106082a8648ce3d030107032200',
            'uncompressed' => '3059301306072a8648ce3d020106082a8648ce3d030107034200',
        ],
    ];

    private const int COORDINATE_BYTES = 32;

    private const string UNCOMPRESSED_MARKER = "\x04";

    private string $x;

    private string $y;

    /**
     * @param string $curve one of the self::CURVE_* constants
     * @param string $compressedPoint 33 bytes: a 0x02/0x03 parity prefix and X
     *
     * @throws IdentityException if the point is not one on the curve, so a
     *                           key that exists is a key that can be used
     *
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Key\VerificationKeyTest::testRejectsAnXThatIsNotOnTheCurve()
     */
    public function __construct(
        public string $curve,
        public string $compressedPoint,
    ) {
        if (!isset(self::CURVES[$this->curve])) {
            throw new IdentityException("Unsupported curve {$this->curve}");
        }

        [$this->x, $this->y] = $this->uncompressed();
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
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Key\VerificationKeyTest::testDerivesTheSameKeyOpensslWould()
     */
    public function der(): string
    {
        return self::header($this->curve, 'uncompressed') . self::UNCOMPRESSED_MARKER . $this->x . $this->y;
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
     * have neither, and .github/workflows/ci.yml has a `no-bignum-extensions`
     * job that builds exactly that.
     *
     * Only a build that refuses falls through, though. One that reads compressed keys and refused this
     * one has said the point is invalid, and the PHP path would spend that
     * 1.5 seconds agreeing: anybody can publish an X that is not on the curve.
     *
     * No test pins this order, and one cannot: the two paths agree by design,
     * so there is no output to assert on, and the difference between them is
     * a duration, which is the one thing a test should not be asserting. Swap
     * the two and the suite stays green while that job's build gets a
     * thousand times slower. This paragraph is the only thing standing in the
     * way, which is why it is still here when its neighbours are not.
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

        $point = self::viaOpenssl($this->curve, $this->compressedPoint);

        if ($point === null && self::opensslReadsCompressedKeys($this->curve)) {
            throw new IdentityException("Compressed point is not a valid point on {$this->curve}");
        }

        return $point ?? self::viaModularSquareRoot($this->curve, $prefix, $xBytes);
    }

    /**
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Key\VerificationKeyTest::testAnInvalidPointIsRejectedWithoutReachingTheFallback()
     */
    private static function opensslReadsCompressedKeys(string $curve): bool
    {
        $generator = hex2bin(self::CURVES[$curve]['g']);

        return $generator !== false && self::viaOpenssl($curve, $generator) !== null;
    }

    /**
     * Null when this OpenSSL will not read the key, for either reason: the
     * build does not accept a compressed SubjectPublicKeyInfo, or the point
     * is not a valid one. {@see self::opensslReadsCompressedKeys()} tells
     * them apart.
     *
     * Leaves OpenSSL's error queue empty either way. The queue is global to
     * the process and appended to, so a key refused here puts entries on it
     * that nothing in this package reads and the caller did not cause. Left
     * there, they surface against whatever the caller does with OpenSSL next.
     *
     * Draining on the way out rather than in also costs the caller any error
     * they had pending, which is not a trade worth making but is the only one
     * PHP offers: the queue cannot be read without consuming it, or restored
     * once it has been.
     *
     * @return array{string, string}|null
     *
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Key\VerificationKeyTest::testLeavesNoOpensslErrorsBehindWhenItRejectsAKey()
     */
    private static function viaOpenssl(string $curve, string $compressedPoint): ?array
    {
        try {
            return self::readWithOpenssl($curve, $compressedPoint);
        } finally {
            while (openssl_error_string() !== false) {
                continue;
            }
        }
    }

    /**
     * @return array{string, string}|null
     */
    private static function readWithOpenssl(string $curve, string $compressedPoint): ?array
    {
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
     * ever on the curve, which on a build that reaches here is the only
     * on-curve check there is.
     *
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Key\VerificationKeyTest::testTheFallbackAgreesWithOpenssl()
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
