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

    public function testFetchesADidPlcDocumentFromThePlcDirectory(): void
    {
        $http = new StubHttpClient([StubHttpClient::json('{"id":"' . self::DID . '"}')]);

        $document = self::resolver($http)->resolve(self::DID);

        self::assertSame(['id' => self::DID], $document);
        self::assertSame(['https://plc.directory/' . self::DID], $http->urls);
    }

    public function testFetchesADidWebDocumentFromTheDomainsWellKnown(): void
    {
        $http = new StubHttpClient([StubHttpClient::json('{"id":"did:web:feed.test"}')]);

        self::resolver($http)->resolve('did:web:feed.test');

        self::assertSame(['https://feed.test/.well-known/did.json'], $http->urls);
    }

    public function testHonoursACustomPlcDirectory(): void
    {
        $http = new StubHttpClient([StubHttpClient::json('{"id":"' . self::DID . '"}')]);

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

    public function testServesAFreshCachedDocumentWithoutFetching(): void
    {
        $http = new StubHttpClient([StubHttpClient::json('{"id":"fetched"}')]);
        $cache = new StubDidDocumentCache();
        $cache->seed(self::DID, ['id' => 'cached'], age: 60);

        $document = self::resolver($http, $cache)->resolve(self::DID);

        self::assertSame(['id' => 'cached'], $document);
        self::assertSame([], $http->urls);
    }

    public function testRefetchesACachedDocumentPastTheStaleBound(): void
    {
        $http = new StubHttpClient([StubHttpClient::json('{"id":"fetched"}')]);
        $cache = new StubDidDocumentCache();
        $cache->seed(self::DID, ['id' => 'cached'], age: 7200);

        $document = self::resolver($http, $cache)->resolve(self::DID);

        self::assertSame(['id' => 'fetched'], $document);
        self::assertSame(1, $cache->writes);
    }

    public function testForceRefreshSkipsAnOtherwiseFreshCachedDocument(): void
    {
        $http = new StubHttpClient([StubHttpClient::json('{"id":"fetched"}')]);
        $cache = new StubDidDocumentCache();
        $cache->seed(self::DID, ['id' => 'cached'], age: 60);

        $document = self::resolver($http, $cache)->resolve(self::DID, forceRefresh: true);

        self::assertSame(['id' => 'fetched'], $document);
    }

    public function testFallsBackToAStaleDocumentWhenTheFetchFails(): void
    {
        $http = new StubHttpClient([new RuntimeException('plc.directory is down')]);
        $cache = new StubDidDocumentCache();
        $cache->seed(self::DID, ['id' => 'cached'], age: 7200);

        $document = self::resolver($http, $cache)->resolve(self::DID);

        self::assertSame(['id' => 'cached'], $document);
        self::assertSame(0, $cache->writes);
    }

    public function testGivesUpWhenTheFetchFailsAndTheCachedDocumentIsPastMaxAge(): void
    {
        $http = new StubHttpClient([new RuntimeException('plc.directory is down')]);
        $cache = new StubDidDocumentCache();
        $cache->seed(self::DID, ['id' => 'cached'], age: 172800);

        $this->expectException(IdentityException::class);

        self::resolver($http, $cache)->resolve(self::DID);
    }

    public function testFetchesFromAHostOnTheAllowList(): void
    {
        $http = new StubHttpClient([StubHttpClient::json('{"id":"did:web:feed.test"}')]);

        self::resolver($http, allowedHosts: ['FEED.test'])->resolve('did:web:feed.test');

        self::assertSame(['https://feed.test/.well-known/did.json'], $http->urls);
    }

    public function testRefusesAHostThatIsNotOnTheAllowList(): void
    {
        $http = new StubHttpClient([StubHttpClient::json('{"id":"did:web:evil.test"}')]);

        $this->expectException(IdentityException::class);

        try {
            self::resolver($http, allowedHosts: ['feed.test'])->resolve('did:web:evil.test');
        } finally {
            self::assertSame([], $http->urls, 'the request must not be sent at all');
        }
    }

    /**
     * Otherwise setting the list at all would break did:plc, and the
     * directory is the caller's own configuration rather than a host any DID
     * picked out.
     */
    public function testStillReachesTheConfiguredPlcDirectoryWithoutListingIt(): void
    {
        $http = new StubHttpClient([StubHttpClient::json('{"id":"' . self::DID . '"}')]);

        self::resolver($http, allowedHosts: ['feed.test'])->resolve(self::DID);

        self::assertSame(['https://plc.directory/' . self::DID], $http->urls);
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
