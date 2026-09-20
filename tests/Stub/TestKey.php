<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Tests\Stub;

use Brick\Math\BigInteger;
use KaranShukla\PhpAtprotoIdentity\DidKey;
use KaranShukla\PhpAtprotoIdentity\VerificationKey;
use OpenSSLAsymmetricKey;
use RuntimeException;

/**
 * A throwaway signing key, published the way a DID document publishes one.
 *
 * Tests need a key they control both halves of: the private half to sign
 * with, and the multibase form a DID document would carry. Generating it
 * keeps the suite free of fixtures and of the network.
 *
 * @internal
 */
final readonly class TestKey
{
    private const string ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

    private function __construct(
        private OpenSSLAsymmetricKey $privateKey,
        public string $multibase,
        /** The PEM OpenSSL itself exports for this key -- the answer we must reproduce. */
        public string $publicPem,
        public string $algorithm,
    ) {}

    public static function secp256k1(): self
    {
        return self::generate('secp256k1', "\xe7\x01", 'ES256K');
    }

    public static function p256(): self
    {
        return self::generate('prime256v1', "\x80\x24", 'ES256');
    }

    /**
     * @return string an ASN.1 signature over $message, made with the private half
     */
    public function sign(string $message): string
    {
        $signature = null;

        if (!openssl_sign($message, $signature, $this->privateKey, \OPENSSL_ALGO_SHA256)
            || !\is_string($signature)
        ) {
            throw new RuntimeException('Could not sign with the generated key');
        }

        return $signature;
    }

    /**
     * The DID document a directory would serve for this key.
     *
     * @return array<string, mixed>
     */
    public function didDocument(string $did): array
    {
        return [
            'id' => $did,
            'verificationMethod' => [
                [
                    'id' => $did . '#atproto',
                    'type' => 'Multikey',
                    'controller' => $did,
                    'publicKeyMultibase' => $this->multibase,
                ],
            ],
        ];
    }

    public function verificationKey(): VerificationKey
    {
        return DidKey::fromMultibase($this->multibase);
    }

    private static function generate(string $curve, string $multicodec, string $algorithm): self
    {
        $key = openssl_pkey_new([
            'private_key_type' => \OPENSSL_KEYTYPE_EC,
            'curve_name' => $curve,
        ]);

        if ($key === false) {
            throw new RuntimeException("Could not generate a {$curve} key");
        }

        $details = openssl_pkey_get_details($key);

        if ($details === false) {
            throw new RuntimeException('Could not read the generated key');
        }

        /** @var array{x: string, y: string} $point */
        $point = $details['ec'];
        $x = str_pad($point['x'], 32, "\x00", \STR_PAD_LEFT);
        $y = str_pad($point['y'], 32, "\x00", \STR_PAD_LEFT);
        $parity = (\ord($y[31]) & 1) === 1 ? "\x03" : "\x02";

        /** @var string $pem */
        $pem = $details['key'];

        return new self($key, 'z' . self::base58($multicodec . $parity . $x), $pem, $algorithm);
    }

    /**
     * Deliberately encodes rather than calling Base58, so the round trip in
     * DidKeyTest runs through two independently written implementations.
     *
     * @param non-empty-string $bytes
     */
    private static function base58(string $bytes): string
    {
        $number = BigInteger::fromBytes($bytes, false);
        $encoded = $number->isZero() ? '' : $number->toArbitraryBase(self::ALPHABET);

        for ($i = 0; $i < \strlen($bytes) && $bytes[$i] === "\x00"; $i++) {
            $encoded = '1' . $encoded;
        }

        return $encoded;
    }
}
