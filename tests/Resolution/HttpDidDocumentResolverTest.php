<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Tests\Resolution;

use GuzzleHttp\Psr7\HttpFactory;
use KaranShukla\PhpAtprotoIdentity\IdentityException;
use KaranShukla\PhpAtprotoIdentity\Resolution\HttpDidDocumentResolver;
use KaranShukla\PhpAtprotoIdentity\Tests\Stub\StubDidDocumentCache;
use KaranShukla\PhpAtprotoIdentity\Tests\Stub\StubHttpClient;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use RuntimeException;

/**
 * @internal
 */
final class HttpDidDocumentResolverTest extends TestCase
{
    private const string DID = 'did:plc:requester';

    private const string WEB_DID = 'did:web:feed.test';

    public function testFetchesADidPlcDocumentFromThePlcDirectory(): void
    {
        $http = new StubHttpClient([StubHttpClient::json(self::body(self::DID, 'fetched'))]);

        $document = self::resolver($http)->resolve(self::DID);

        self::assertSame(self::document(self::DID, 'fetched'), $document);
        self::assertSame(['https://plc.directory/' . self::DID], $http->urls);
    }

    public function testFetchesADidWebDocumentFromTheDomainsWellKnown(): void
    {
        $http = new StubHttpClient([StubHttpClient::json(self::body(self::WEB_DID, 'fetched'))]);

        self::resolver($http)->resolve(self::WEB_DID);

        self::assertSame(['https://feed.test/.well-known/did.json'], $http->urls);
    }

    public function testHonoursACustomPlcDirectory(): void
    {
        $http = new StubHttpClient([StubHttpClient::json(self::body(self::DID, 'fetched'))]);

        new HttpDidDocumentResolver(
            httpClient: $http,
            requestFactory: new HttpFactory(),
            plcDirectory: 'https://plc.example.test/',
        )->resolve(self::DID);

        self::assertSame(['https://plc.example.test/' . self::DID], $http->urls);
    }

    public function testRejectsADidMethodItCannotResolve(): void
    {
        $this->expectException(IdentityException::class);

        self::resolver(new StubHttpClient([]))->resolve('did:example:nope');
    }

    public function testRejectsADidWebWithAPath(): void
    {
        $this->expectException(IdentityException::class);

        self::resolver(new StubHttpClient([]))->resolve('did:web:feed.test:user:alice');
    }

    public function testRejectsANonOkResponse(): void
    {
        $http = new StubHttpClient([StubHttpClient::json('', 404)]);

        $this->expectException(IdentityException::class);

        self::resolver($http)->resolve(self::DID);
    }

    public function testRejectsABodyThatIsNotAJsonObject(): void
    {
        $http = new StubHttpClient([StubHttpClient::json('"not an object"')]);

        $this->expectException(IdentityException::class);

        self::resolver($http)->resolve(self::DID);
    }

    /** A JSON array decodes to a PHP array, which is_array() alone allows. */
    public function testRejectsABodyThatIsAJsonArray(): void
    {
        $http = new StubHttpClient([StubHttpClient::json('[{"id":"' . self::DID . '"}]')]);

        $this->expectException(IdentityException::class);
        $this->expectExceptionMessage('not a JSON object');

        self::resolver($http)->resolve(self::DID);
    }

    /**
     * A did:web is served by the host the DID names, so without this check
     * any host can publish a document claiming to be any other DID, and a
     * caller reading a key out of it would verify that DID's tokens against a
     * key its owner never published.
     */
    public function testRefusesADocumentClaimingADifferentDid(): void
    {
        $http = new StubHttpClient([StubHttpClient::json(self::body(self::DID, 'impersonated'))]);

        $this->expectException(IdentityException::class);
        $this->expectExceptionMessage('claims to be ' . self::DID);

        self::resolver($http)->resolve('did:web:evil.test');
    }

    public function testRefusesADocumentWithNoIdAtAll(): void
    {
        $http = new StubHttpClient([StubHttpClient::json('{"verificationMethod":[]}')]);

        $this->expectException(IdentityException::class);
        $this->expectExceptionMessage('no id');

        self::resolver($http)->resolve(self::DID);
    }

    public function testRefusesADocumentTooLargeToBeOne(): void
    {
        $padding = str_repeat('a', HttpDidDocumentResolver::MAX_DOCUMENT_BYTES);
        $http = new StubHttpClient([
            StubHttpClient::json('{"id":"' . self::DID . '","padding":"' . $padding . '"}'),
        ]);

        $this->expectException(IdentityException::class);
        $this->expectExceptionMessage('larger than');

        self::resolver($http)->resolve(self::DID);
    }

    public function testServesAFreshCachedDocumentWithoutFetching(): void
    {
        $http = new StubHttpClient([StubHttpClient::json(self::body(self::DID, 'fetched'))]);
        $cache = new StubDidDocumentCache();
        $cache->seed(self::DID, self::document(self::DID, 'cached'), age: 60);

        $document = self::resolver($http, $cache)->resolve(self::DID);

        self::assertSame(self::document(self::DID, 'cached'), $document);
        self::assertSame([], $http->urls);
    }

    public function testRefetchesACachedDocumentPastTheStaleBound(): void
    {
        $http = new StubHttpClient([StubHttpClient::json(self::body(self::DID, 'fetched'))]);
        $cache = new StubDidDocumentCache();
        $cache->seed(self::DID, self::document(self::DID, 'cached'), age: 7200);

        $document = self::resolver($http, $cache)->resolve(self::DID);

        self::assertSame(self::document(self::DID, 'fetched'), $document);
        self::assertSame(1, $cache->writes);
    }

    public function testForceRefreshSkipsAnOtherwiseFreshCachedDocument(): void
    {
        $http = new StubHttpClient([StubHttpClient::json(self::body(self::DID, 'fetched'))]);
        $cache = new StubDidDocumentCache();
        $cache->seed(self::DID, self::document(self::DID, 'cached'), age: 60);

        $document = self::resolver($http, $cache)->resolve(self::DID, forceRefresh: true);

        self::assertSame(self::document(self::DID, 'fetched'), $document);
    }

    public function testFallsBackToAStaleDocumentWhenTheFetchFails(): void
    {
        $http = new StubHttpClient([new RuntimeException('plc.directory is down')]);
        $cache = new StubDidDocumentCache();
        $cache->seed(self::DID, self::document(self::DID, 'cached'), age: 7200);

        $document = self::resolver($http, $cache)->resolve(self::DID);

        self::assertSame(self::document(self::DID, 'cached'), $document);
        self::assertSame(0, $cache->writes);
    }

    public function testGivesUpWhenTheFetchFailsAndTheCachedDocumentIsPastMaxAge(): void
    {
        $http = new StubHttpClient([new RuntimeException('plc.directory is down')]);
        $cache = new StubDidDocumentCache();
        $cache->seed(self::DID, self::document(self::DID, 'cached'), age: 172800);

        $this->expectException(IdentityException::class);

        self::resolver($http, $cache)->resolve(self::DID);
    }

    public function testFetchesFromAHostOnTheAllowList(): void
    {
        $http = new StubHttpClient([StubHttpClient::json(self::body(self::WEB_DID, 'fetched'))]);

        self::resolver($http, allowedHosts: ['FEED.test'])->resolve(self::WEB_DID);

        self::assertSame(['https://feed.test/.well-known/did.json'], $http->urls);
    }

    public function testRefusesAHostThatIsNotOnTheAllowList(): void
    {
        $http = new StubHttpClient([StubHttpClient::json(self::body('did:web:evil.test', 'fetched'))]);

        $this->expectException(IdentityException::class);

        try {
            self::resolver($http, allowedHosts: ['feed.test'])->resolve('did:web:evil.test');
        } finally {
            self::assertSame([], $http->urls, 'the request must not be sent at all');
        }
    }

    /**
     * An entry with no port means 443. Otherwise listing a host would hand a
     * DID every other port on that machine, which is the thing the list was
     * set to prevent.
     */
    public function testRefusesAnAllowedHostOnAPortThatWasNotListed(): void
    {
        $http = new StubHttpClient([]);

        $this->expectException(IdentityException::class);
        $this->expectExceptionMessage('feed.test:9200');

        self::resolver($http, allowedHosts: ['feed.test'])->resolve('did:web:feed.test%3A9200');
    }

    public function testFetchesFromAnAllowedHostOnAPortThatWasListed(): void
    {
        $did = 'did:web:feed.test%3A8443';
        $http = new StubHttpClient([StubHttpClient::json(self::body($did, 'fetched'))]);

        self::resolver($http, allowedHosts: ['feed.test:8443'])->resolve($did);

        self::assertSame(['https://feed.test:8443/.well-known/did.json'], $http->urls);
    }

    /**
     * Otherwise setting the list at all would break did:plc, and the
     * directory is the caller's own configuration rather than a host any DID
     * picked out.
     */
    public function testStillReachesTheConfiguredPlcDirectoryWithoutListingIt(): void
    {
        $http = new StubHttpClient([StubHttpClient::json(self::body(self::DID, 'fetched'))]);

        self::resolver($http, allowedHosts: ['feed.test'])->resolve(self::DID);

        self::assertSame(['https://plc.directory/' . self::DID], $http->urls);
    }

    /**
     * A refused host is refused whether or not there is something cached for
     * it. Validation used to sit inside the same try as the fetch, so a
     * refusal read as an outage and the stale document was served instead.
     */
    public function testDoesNotServeARefusedHostFromTheCache(): void
    {
        $cache = new StubDidDocumentCache();
        $cache->seed('did:web:evil.test', self::document('did:web:evil.test', 'cached'), age: 7200);

        $this->expectException(IdentityException::class);
        $this->expectExceptionMessage('not allowed to fetch');

        self::resolver(new StubHttpClient([]), $cache, allowedHosts: ['feed.test'])
            ->resolve('did:web:evil.test');
    }

    public function testDoesNotServeAnUnresolvableDidMethodFromTheCache(): void
    {
        $cache = new StubDidDocumentCache();
        $cache->seed('did:example:nope', self::document('did:example:nope', 'cached'), age: 7200);

        $this->expectException(IdentityException::class);
        $this->expectExceptionMessage('Unsupported DID method');

        self::resolver(new StubHttpClient([]), $cache)->resolve('did:example:nope');
    }

    public function testDoesNotServeAMalformedDidFromTheCache(): void
    {
        $did = 'did:web:feed.test%2F..%2Fadmin';
        $cache = new StubDidDocumentCache();
        $cache->seed($did, self::document($did, 'cached'), age: 7200);

        $this->expectException(IdentityException::class);
        $this->expectExceptionMessage('Malformed DID identifier');

        self::resolver(new StubHttpClient([]), $cache)->resolve($did);
    }

    /**
     * @return array<string, mixed>
     */
    private static function document(string $did, string $source): array
    {
        return ['id' => $did, 'source' => $source];
    }

    private static function body(string $did, string $source): string
    {
        return json_encode(self::document($did, $source), \JSON_THROW_ON_ERROR);
    }

    /**
     * @param list<string> $allowedHosts
     */
    private static function resolver(
        ClientInterface $http,
        ?StubDidDocumentCache $cache = null,
        array $allowedHosts = [],
    ): HttpDidDocumentResolver {
        return new HttpDidDocumentResolver(
            httpClient: $http,
            requestFactory: new HttpFactory(),
            cache: $cache ?? new StubDidDocumentCache(),
            allowedHosts: $allowedHosts,
        );
    }
}
