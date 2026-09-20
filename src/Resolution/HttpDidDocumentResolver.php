<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Resolution;

use KaranShukla\PhpAtprotoIdentity\IdentityException;
use KaranShukla\PhpAtprotoIdentity\Resolution\Cache\DidDocumentCache;
use KaranShukla\PhpAtprotoIdentity\Resolution\Cache\NullDidDocumentCache;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamInterface;
use Throwable;

/**
 * The two freshness bounds match @atproto/identity's MemoryCache.
 *
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\HttpDidDocumentResolverTest::testServesAFreshCachedDocumentWithoutFetching()
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\HttpDidDocumentResolverTest::testRefetchesACachedDocumentPastTheStaleBound()
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\HttpDidDocumentResolverTest::testFallsBackToAStaleDocumentWhenTheFetchFails()
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\HttpDidDocumentResolverTest::testGivesUpWhenTheFetchFailsAndTheCachedDocumentIsPastMaxAge()
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\HttpDidDocumentResolverTest::testDoesNotServeARefusedHostFromTheCache()
 */
final readonly class HttpDidDocumentResolver implements DidDocumentResolver
{
    public const int SERVE_WITHOUT_FETCHING_UNDER = 3600;

    public const int SERVE_ON_FETCH_FAILURE_UNDER = 86400;

    public const string PLC_DIRECTORY = 'https://plc.directory';

    /**
     * Bounds what is decoded and held, not what crosses the wire: bounding
     * the transfer is the HTTP client's job, the same way redirects are.
     *
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\HttpDidDocumentResolverTest::testRefusesADocumentTooLargeToBeOne()
     */
    public const int MAX_DOCUMENT_BYTES = 262144;

    private const int HTTPS_PORT = 443;

    /**
     * @see self::checkHostIsAPublicDomain()
     */
    private const string PUBLIC_DOMAIN = '/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z](?:[a-z0-9-]*[a-z0-9])?$/i';

    /**
     * @param list<string> $allowedHosts the only hosts this resolver may
     *                                   fetch from, besides the PLC
     *                                   directory's own. An entry may pin a
     *                                   port (`pds.example.com:8443`); one
     *                                   that does not means port 443. Empty
     *                                   means any public domain, which is
     *                                   also why naming a host here is how
     *                                   you reach one that is not
     *                                   (`localhost:3000`)
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
        $url = DidDocumentUrl::for($did, $this->plcDirectory);

        $this->checkHostIsAllowed($url);

        $cached = $this->cache->get($did);

        if (!$forceRefresh && $cached !== null && $cached['age'] < $this->staleAfter) {
            return $cached['document'];
        }

        try {
            $document = $this->fetch($did, $url);
        } catch (Throwable $e) {
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
    private function fetch(string $did, string $url): array
    {
        $response = $this->httpClient->sendRequest(
            $this->requestFactory->createRequest('GET', $url)
                ->withHeader('Accept', 'application/json'),
        );

        if ($response->getStatusCode() !== 200) {
            throw new IdentityException("DID resolution returned HTTP {$response->getStatusCode()}");
        }

        $document = json_decode(self::body($response->getBody()), true);

        if (!self::isJsonObject($document)) {
            throw new IdentityException('DID document is not a JSON object');
        }

        self::checkDocumentIsFor($did, $document);

        return $document;
    }

    /**
     * @phpstan-assert-if-true array<string, mixed> $decoded
     *
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\HttpDidDocumentResolverTest::testRejectsABodyThatIsAJsonArray()
     */
    private static function isJsonObject(mixed $decoded): bool
    {
        return \is_array($decoded) && ($decoded === [] || !array_is_list($decoded));
    }

    /**
     * DID Core requires a document's `id` to match the DID it was fetched
     * for.
     *
     * @param array<string, mixed> $document
     *
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\HttpDidDocumentResolverTest::testRefusesADocumentClaimingADifferentDid()
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\HttpDidDocumentResolverTest::testRefusesADocumentWhoseIdDiffersOnlyInCase()
     */
    private static function checkDocumentIsFor(string $did, array $document): void
    {
        $id = $document['id'] ?? null;

        if ($id !== $did) {
            throw new IdentityException(\sprintf(
                'DID document claims to be %s',
                \is_string($id) ? $id : 'a document with no id',
            ));
        }
    }

    /**
     * PSR-7's read() may return fewer bytes than asked for, so this goes
     * round until the stream ends or the bound does.
     *
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\HttpDidDocumentResolverTest::testRefusesADocumentTooLargeToBeOne()
     */
    private static function body(StreamInterface $stream): string
    {
        $json = '';

        while (\strlen($json) <= self::MAX_DOCUMENT_BYTES && !$stream->eof()) {
            $chunk = $stream->read(self::MAX_DOCUMENT_BYTES + 1 - \strlen($json));

            if ($chunk === '') {
                break;
            }

            $json .= $chunk;
        }

        if (\strlen($json) > self::MAX_DOCUMENT_BYTES) {
            throw new IdentityException(
                \sprintf('DID document is larger than %d bytes', self::MAX_DOCUMENT_BYTES),
            );
        }

        return $json;
    }

    /**
     * Bounds where a request is addressed, not where it ends up: an allowed
     * host can still answer with a 302.
     *
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\HttpDidDocumentResolverTest::testRefusesAHostThatIsNotOnTheAllowList()
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\HttpDidDocumentResolverTest::testRefusesAnAllowedHostOnAPortThatWasNotListed()
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\HttpDidDocumentResolverTest::testRefusesAHostThatIsNotAPublicDomain()
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\HttpDidDocumentResolverTest::testFetchesFromALocalHostThatWasNamedOnTheAllowList()
     */
    private function checkHostIsAllowed(string $url): void
    {
        $authority = self::authorityOfUrl($url);

        if ($authority === self::authorityOfUrl($this->plcDirectory)) {
            return;
        }

        if ($this->allowedHosts !== []) {
            if (!\in_array($authority, array_map(self::authorityOfEntry(...), $this->allowedHosts), true)) {
                throw new IdentityException("DID resolution is not allowed to fetch from {$authority}");
            }

            return;
        }

        self::checkHostIsAPublicDomain($url, $authority);
    }

    /**
     * A blunt instrument: a public name with a private A record passes, as
     * does `metadata.google.internal`.
     *
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\HttpDidDocumentResolverTest::testRefusesAHostThatIsNotAPublicDomain()
     */
    private static function checkHostIsAPublicDomain(string $url, string $authority): void
    {
        $host = (string) parse_url($url, \PHP_URL_HOST);

        if (preg_match(self::PUBLIC_DOMAIN, $host) !== 1) {
            throw new IdentityException(
                "DID resolution will not fetch from {$authority}, which is not a public domain; "
                . 'name it in allowedHosts if that is what you meant',
            );
        }
    }

    private static function authorityOfUrl(string $url): string
    {
        $host = strtolower((string) parse_url($url, \PHP_URL_HOST));
        $port = parse_url($url, \PHP_URL_PORT);

        if (!\is_int($port)) {
            $port = parse_url($url, \PHP_URL_SCHEME) === 'http' ? 80 : self::HTTPS_PORT;
        }

        return "{$host}:{$port}";
    }

    /**
     * Split on the last colon rather than parsed, because parse_url reads a
     * leading `host:` as a scheme.
     */
    private static function authorityOfEntry(string $entry): string
    {
        $entry = strtolower(trim($entry));
        $colon = strrpos($entry, ':');

        if ($colon === false) {
            return "{$entry}:" . self::HTTPS_PORT;
        }

        return $entry;
    }
}
