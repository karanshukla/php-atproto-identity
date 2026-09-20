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
 * Resolves did:plc via a PLC directory and did:web via the domain's
 * .well-known/did.json.
 *
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
     * A DID document is a small object -- a PLC one is about a kilobyte --
     * and for did:web its length is chosen by whoever the DID names. So only
     * this much of a response is read, and a body still going at the end of
     * it is refused rather than parsed.
     *
     * This bounds what is decoded and held, not what crosses the wire: an
     * HTTP client that buffers a whole response before returning it has
     * already paid for the body by the time this runs. Bounding the transfer
     * is the client's job, the same way following redirects is.
     */
    public const int MAX_DOCUMENT_BYTES = 262144;

    /**
     * The port a did:web is fetched on, and so the one an allowlist entry
     * means when it does not say.
     */
    private const int HTTPS_PORT = 443;

    /**
     * @param list<string> $allowedHosts the only hosts this resolver may
     *                                   fetch from, besides the PLC
     *                                   directory's own; empty means any.
     *                                   An entry may pin a port
     *                                   (`pds.example.com:8443`); one that
     *                                   does not means port 443
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
        // Ahead of the cache read and outside the try below, both on purpose.
        // A DID whose method we do not resolve, whose identifier is malformed
        // or whose host the caller has refused is not a DID this resolver
        // answers for, and serving one out of the cache because the network
        // happens to be down would be answering for it. Only a fetch that was
        // allowed to happen and then failed reaches the stale-document path.
        $url = DidDocumentUrl::for($did, $this->plcDirectory);

        $this->checkHostIsAllowed($url);

        $cached = $this->cache->get($did);

        if (!$forceRefresh && $cached !== null && $cached['age'] < $this->staleAfter) {
            return $cached['document'];
        }

        try {
            $document = $this->fetch($did, $url);
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

        // A JSON array decodes to a PHP array too, and an empty object is
        // indistinguishable from one, so the list check spares the real
        // mismatch message below for the case it describes.
        if (!\is_array($document) || ($document !== [] && array_is_list($document))) {
            throw new IdentityException('DID document is not a JSON object');
        }

        /** @var array<string, mixed> $document */
        self::checkDocumentIsFor($did, $document);

        return $document;
    }

    /**
     * A document has to claim the DID it was fetched for.
     *
     * For did:web the host serving the document is named by the DID, so
     * without this any host can publish a document claiming to be any other
     * DID, and a caller that reads a `#atproto` key out of it then verifies
     * that DID's tokens against a key its owner never published. DID Core
     * requires the `id` to match and @atproto/identity checks it; this is
     * that check.
     *
     * The comparison is exact. ATProto DIDs are lowercase, and a did:web
     * whose case does not match the document it fetched is a misconfiguration
     * worth failing loudly on rather than papering over.
     *
     * @param array<string, mixed> $document
     *
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\HttpDidDocumentResolverTest::testRefusesADocumentClaimingADifferentDid()
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
     * Reads at most {@see self::MAX_DOCUMENT_BYTES}, and refuses a body that
     * is still going after that. A single read() is allowed to return less
     * than it was asked for, so this goes round until the stream ends or the
     * bound does.
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
     * A did:web names the host its document is fetched from, so a caller
     * resolving DIDs it has no reason to trust can hold that host to a list
     * rather than to a hostname's grammar.
     *
     * An entry is a host, optionally with a port. Without one it means 443,
     * rather than any port: once a host is on the list, a DID that picks the
     * port too would otherwise reach whatever else that machine happens to be
     * running, which is the thing the list was set to prevent.
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
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Resolution\HttpDidDocumentResolverTest::testRefusesAnAllowedHostOnAPortThatWasNotListed()
     */
    private function checkHostIsAllowed(string $url): void
    {
        if ($this->allowedHosts === []) {
            return;
        }

        $authority = self::authorityOfUrl($url);
        $allowed = [
            ...array_map(self::authorityOfEntry(...), $this->allowedHosts),
            self::authorityOfUrl($this->plcDirectory),
        ];

        if (!\in_array($authority, $allowed, true)) {
            throw new IdentityException("DID resolution is not allowed to fetch from {$authority}");
        }
    }

    /**
     * The host and port a URL addresses, with the port filled in from the
     * scheme when it is not written out, so that `https://feed.test` and
     * `https://feed.test:443` are the one thing.
     */
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
     * The same, for an allowlist entry, which is a bare host rather than a
     * URL. Split on the last colon rather than parsed, because parse_url
     * reads a leading `host:` as a scheme.
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
