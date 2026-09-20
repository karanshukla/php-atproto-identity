<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Tests\Integration;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\HttpFactory;
use KaranShukla\PhpAtprotoIdentity\IdentityException;
use KaranShukla\PhpAtprotoIdentity\Key\DidKey;
use KaranShukla\PhpAtprotoIdentity\Key\VerificationKey;
use KaranShukla\PhpAtprotoIdentity\Resolution\Cache\Psr6DidDocumentCache;
use KaranShukla\PhpAtprotoIdentity\Resolution\HttpDidDocumentResolver;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * Talks to the real PLC directory over the real network. The unit suite proves
 * the resolver builds the right URL; only this proves the directory still
 * answers it in the shape the rest of the library expects.
 *
 * @internal
 */
#[Group('integration')]
final class DidResolutionTest extends TestCase
{
    /**
     * bsky.app's own account. A DID is permanent by construction, and this one
     * belongs to the service itself, so it outlives any individual's handle.
     */
    private const string BSKY_APP = 'did:plc:z72i7hdynmk6r22z27h6tvur';

    /**
     * did:web accounts are individually operated, so there is no institutional
     * one to point at. This is a real registered account -- the appview
     * resolves the handle dead10ck.dev to it -- but if this test starts failing
     * alone, check whether the domain still serves a document before assuming
     * the resolver broke.
     */
    private const string DID_WEB = 'did:web:dead10ck.dev';

    public function testResolvesALiveDidPlcDocument(): void
    {
        $document = self::resolver()->resolve(self::BSKY_APP);

        $aliases = $document['alsoKnownAs'] ?? null;

        self::assertSame(self::BSKY_APP, $document['id']);
        self::assertIsArray($aliases);
        self::assertContains('at://bsky.app', $aliases);
    }

    /**
     * The end of the pipeline that matters to a caller: a DID goes in, and a
     * key OpenSSL will actually load comes out.
     */
    public function testTurnsTheLivePublicKeyIntoSomethingOpensslLoads(): void
    {
        $document = self::resolver()->resolve(self::BSKY_APP);
        $key = DidKey::fromMultibase(self::atprotoMultibase($document));

        self::assertSame(VerificationKey::CURVE_SECP256K1, $key->curve);

        $public = openssl_pkey_get_public($key->pem());

        self::assertNotFalse($public, 'OpenSSL rejected the PEM built from the live document');

        $details = openssl_pkey_get_details($public);

        self::assertIsArray($details);
        self::assertIsArray($details['ec']);
        self::assertSame('secp256k1', $details['ec']['curve_name']);
    }

    public function testReportsAnUnresolvableDidAsAnIdentityException(): void
    {
        $this->expectException(IdentityException::class);

        // Structurally valid, so it reaches the directory and comes back 404.
        self::resolver()->resolve('did:plc:aaaaaaaaaaaaaaaaaaaaaaaa');
    }

    public function testASecondResolveIsServedFromTheCacheWithoutASecondRequest(): void
    {
        $counter = new class(new Client(['timeout' => 10])) implements ClientInterface {
            public int $requests = 0;

            public function __construct(private ClientInterface $inner) {}

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                $this->requests++;

                return $this->inner->sendRequest($request);
            }
        };

        $resolver = new HttpDidDocumentResolver(
            $counter,
            new HttpFactory(),
            new Psr6DidDocumentCache(new ArrayAdapter()),
        );

        $first = $resolver->resolve(self::BSKY_APP);
        $second = $resolver->resolve(self::BSKY_APP);

        self::assertSame($first, $second);
        self::assertSame(1, $counter->requests, 'the directory was hit twice for one DID');
    }

    /**
     * The other half of documentUrl(): a domain's own .well-known, fetched over
     * real HTTPS rather than a stub that only proves we built the URL.
     */
    public function testResolvesALiveDidWebDocument(): void
    {
        $document = self::resolver()->resolve(self::DID_WEB);

        self::assertSame(self::DID_WEB, $document['id']);

        $key = DidKey::fromMultibase(self::atprotoMultibase($document));

        self::assertSame(VerificationKey::CURVE_SECP256K1, $key->curve);
        self::assertNotFalse(openssl_pkey_get_public($key->pem()));
    }

    public function testRejectsADidWebCarryingAPath(): void
    {
        $this->expectException(IdentityException::class);

        self::resolver()->resolve('did:web:example.com:user:alice');
    }

    private static function resolver(): HttpDidDocumentResolver
    {
        return new HttpDidDocumentResolver(new Client(['timeout' => 10]), new HttpFactory());
    }

    /**
     * @param array<string, mixed> $document
     */
    private static function atprotoMultibase(array $document): string
    {
        $methods = $document['verificationMethod'] ?? null;

        self::assertIsArray($methods);

        foreach ($methods as $method) {
            self::assertIsArray($method);
            self::assertIsString($method['id']);

            if (str_ends_with($method['id'], '#atproto')) {
                self::assertIsString($method['publicKeyMultibase']);

                return $method['publicKeyMultibase'];
            }
        }

        self::fail('the live document has no #atproto verification method');
    }
}
