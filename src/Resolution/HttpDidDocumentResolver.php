<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Resolution;

use KaranShukla\PhpAtprotoIdentity\IdentityException;
use KaranShukla\PhpAtprotoIdentity\Resolution\Cache\DidDocumentCache;
use KaranShukla\PhpAtprotoIdentity\Resolution\Cache\NullDidDocumentCache;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Throwable;

/**
 * Resolves did:plc via a PLC directory and did:web via the domain's
 * .well-known/did.json.
 *
 * The two freshness bounds match @atproto/identity's MemoryCache.
 *
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\HttpDidDocumentResolverTest::testServesAFreshCachedDocumentWithoutFetching()
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\HttpDidDocumentResolverTest::testRefetchesACachedDocumentPastTheStaleBound()
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\HttpDidDocumentResolverTest::testFallsBackToAStaleDocumentWhenTheFetchFails()
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\HttpDidDocumentResolverTest::testGivesUpWhenTheFetchFailsAndTheCachedDocumentIsPastMaxAge()
 */
final readonly class HttpDidDocumentResolver implements DidDocumentResolver
{
    public const int SERVE_WITHOUT_FETCHING_UNDER = 3600;

    public const int SERVE_ON_FETCH_FAILURE_UNDER = 86400;

    public const string PLC_DIRECTORY = 'https://plc.directory';

    /**
     * @param list<string> $allowedHosts the only hosts this resolver may
     *                                   fetch from, besides the PLC
     *                                   directory's own; empty means any
     */
    public function __construct(
        private ClientInterface $httpClient,
        private RequestFactoryInterface $requestFactory,
        private DidDocumentCache $cache = new NullDidDocumentCache(),
        private string $plcDirectory = self::PLC_DIRECTORY,
        private int $staleAfter = self::SERVE_WITHOUT_FETCHING_UNDER,
        private int $maxAge = self::SERVE_ON_FETCH_FAILURE_UNDER,
        private array $allowedHosts = [],
    ) {}

    public function resolve(string $did, bool $forceRefresh = false): array
    {
        $cached = $this->cache->get($did);

        if (!$forceRefresh && $cached !== null && $cached['age'] < $this->staleAfter) {
            return $cached['document'];
        }

        try {
            $document = $this->fetch($did);
        } catch (Throwable $e) {
            // A directory outage should not take a service down with it, so a
            // document that is merely stale is still better than nothing.
            if ($cached !== null && $cached['age'] < $this->maxAge) {
                return $cached['document'];
            }

            throw new IdentityException("Could not resolve {$did}: {$e->getMessage()}", previous: $e);
        }

        $this->cache->put($did, $document);

        return $document;
    }

    /**
     * @return array<string, mixed>
     */
    private function fetch(string $did): array
    {
        $url = DidDocumentUrl::for($did, $this->plcDirectory);

        $this->checkHostIsAllowed($url);

        $response = $this->httpClient->sendRequest(
            $this->requestFactory->createRequest('GET', $url)
                ->withHeader('Accept', 'application/json'),
        );

        if ($response->getStatusCode() !== 200) {
            throw new IdentityException("DID resolution returned HTTP {$response->getStatusCode()}");
        }

        $document = json_decode((string) $response->getBody(), true);

        if (!\is_array($document)) {
            throw new IdentityException('DID document is not a JSON object');
        }

        /** @var array<string, mixed> $document */
        return $document;
    }

    /**
     * A did:web names the host its document is fetched from, so a caller
     * resolving DIDs it has no reason to trust can hold that host to a list
     * rather than to a hostname's grammar.
     *
     * The configured PLC directory is always allowed without being listed:
     * it is the caller's own configuration rather than anything a DID chose,
     * and leaving it out would break did:plc for everyone who sets the list.
     *
     * This bounds where a request is addressed, not where it ends up. A
     * client that follows redirects can still be sent elsewhere by an
     * allowed host, which is the HTTP client's business to refuse.
     *
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\HttpDidDocumentResolverTest::testRefusesAHostThatIsNotOnTheAllowList()
     */
    private function checkHostIsAllowed(string $url): void
    {
        if ($this->allowedHosts === []) {
            return;
        }

        $host = self::host($url);
        $allowed = array_map(strtolower(...), [...$this->allowedHosts, self::host($this->plcDirectory)]);

        if (!\in_array($host, $allowed, true)) {
            throw new IdentityException("DID resolution is not allowed to fetch from {$host}");
        }
    }

    /**
     * The hostname a URL addresses, without its port: a port is not what the
     * list is about, and demanding one in every entry only invites a typo.
     */
    private static function host(string $url): string
    {
        return strtolower((string) parse_url($url, \PHP_URL_HOST));
    }
}
