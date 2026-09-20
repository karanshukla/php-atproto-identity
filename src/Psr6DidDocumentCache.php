<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity;

use Psr\Cache\CacheItemPoolInterface;

/**
 * Backs the DID document cache with any PSR-6 pool.
 *
 * PSR-6 reports validity but not age, so the fetch time is stored alongside
 * the document and the item's own expiry is only the outer bound.
 *
 * @see \KaranShukla\PhpAtprotoIdentity\Tests\Psr6DidDocumentCacheTest
 */
final readonly class Psr6DidDocumentCache implements DidDocumentCache
{
    /**
     * @param int $ttl outer bound; below the resolver's $maxAge, a
     *                 stale-but-servable document expires before it is needed
     */
    public function __construct(
        private CacheItemPoolInterface $cache,
        private int $ttl = HttpDidDocumentResolver::SERVE_ON_FETCH_FAILURE_UNDER,
        private string $prefix = 'atproto_did_document_',
    ) {}

    public function get(string $did): ?array
    {
        $item = $this->cache->getItem($this->key($did));

        if (!$item->isHit()) {
            return null;
        }

        $stored = $item->get();

        if (!\is_array($stored) || !\is_array($stored['document'] ?? null) || !\is_int($stored['fetchedAt'] ?? null)) {
            return null;
        }

        /** @var array<string, mixed> $document */
        $document = $stored['document'];

        return [
            'document' => $document,
            'age' => max(0, time() - $stored['fetchedAt']),
        ];
    }

    public function put(string $did, array $document): void
    {
        $item = $this->cache->getItem($this->key($did));
        $item->set(['document' => $document, 'fetchedAt' => time()]);
        $item->expiresAfter($this->ttl);
        $this->cache->save($item);
    }

    /**
     * A DID contains characters PSR-6 reserves in a key, so it is hashed.
     *
     * @see \KaranShukla\PhpAtprotoIdentity\Tests\Psr6DidDocumentCacheTest::testKeepsDocumentsForDifferentDidsApart()
     */
    private function key(string $did): string
    {
        return $this->prefix . md5($did);
    }
}
