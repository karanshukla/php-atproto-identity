<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity;

/**
 * An elliptic-curve public key recovered from a DID document, in a form
 * OpenSSL will accept.
 *
 * ATProto publishes signing keys as compressed points inside a multibase
 * string -- an X coordinate and one bit of Y -- while verifiers want a
 * PEM-encoded SubjectPublicKeyInfo over an uncompressed one. Recovering Y
 * means a modular square root in the curve's field, which is a job for C and
 * not for PHP: see {@see self::uncompressed()}.
 *
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\VerificationKeyTest
 */
final readonly class VerificationKey
{
    public const string CURVE_SECP256K1 = 'secp256k1';

    public const string CURVE_P256 = 'p256';

    /**
     * Per curve: the JWS algorithm a token signed by it declares, and the two
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
            // ... OID 1.2.840.10045.2.1 ecPublicKey, OID 1.3.132.0.10 secp256k1
            'compressed' => '3036301006072a8648ce3d020106052b8104000a032200',
            'uncompressed' => '3056301006072a8648ce3d020106052b8104000a034200',
        ],
        self::CURVE_P256 => [
            'algorithm' => 'ES256',
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
     * RFC 5480 lets a SubjectPublicKeyInfo carry its point in compressed
     * form, so the key can be handed to OpenSSL exactly as published and read
     * back decompressed. That puts the square root in C rather than in a
     * bignum library -- the difference between a millisecond and well over a
     * second when no bignum extension is loaded -- and gets OpenSSL's own
     * on-curve validation for free.
     *
     * @return array{string, string} X and Y, each left-padded to 32 bytes
     */
    private function uncompressed(): array
    {
        if (\strlen($this->compressedPoint) !== self::COORDINATE_BYTES + 1) {
            throw new IdentityException('Compressed point must be 33 bytes');
        }

        $prefix = \ord($this->compressedPoint[0]);

        if ($prefix !== 0x02 && $prefix !== 0x03) {
            throw new IdentityException(\sprintf('Unexpected point prefix 0x%02x', $prefix));
        }

        // Drain anything an earlier call left in OpenSSL's error queue, so a
        // failure below is reported with this key's error and not that one.
        while (openssl_error_string() !== false) {
            continue;
        }

        $public = openssl_pkey_get_public(
            self::wrap(self::header($this->curve, 'compressed') . $this->compressedPoint),
        );

        if ($public === false) {
            throw new IdentityException(\sprintf(
                'Could not read the published signing key: %s',
                openssl_error_string() ?: "the point does not lie on {$this->curve}",
            ));
        }

        $details = openssl_pkey_get_details($public);
        $point = $details === false ? null : $details['ec'] ?? null;

        if (!\is_array($point)) {
            throw new IdentityException('OpenSSL did not report an EC point for this key');
        }

        $x = $point['x'] ?? null;
        $y = $point['y'] ?? null;

        if (!\is_string($x) || !\is_string($y)) {
            throw new IdentityException('OpenSSL did not report the key coordinates');
        }

        return [self::coordinate($x), self::coordinate($y)];
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
     * OpenSSL emits a coordinate with its leading zero bytes stripped; the
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
