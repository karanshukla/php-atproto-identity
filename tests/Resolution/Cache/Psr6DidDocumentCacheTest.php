<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Tests\Resolution\Cache;

use KaranShukla\PhpAtprotoIdentity\Resolution\Cache\Psr6DidDocumentCache;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * @internal
 */
final class Psr6DidDocumentCacheTest extends TestCase
{
    private const string DID = 'did:plc:requester';

    public function testReturnsNullForADidItHasNotSeen(): void
    {
        self::assertNull(new Psr6DidDocumentCache(new ArrayAdapter())->get(self::DID));
    }

    public function testRoundTripsADocumentWithAnAge(): void
    {
        $cache = new Psr6DidDocumentCache(new ArrayAdapter());
        $cache->put(self::DID, ['id' => self::DID]);

        $entry = $cache->get(self::DID);

        self::assertNotNull($entry);
        self::assertSame(['id' => self::DID], $entry['document']);
        // Just written, so the only honest assertion is that the age is small.
        self::assertLessThanOrEqual(1, $entry['age']);
    }

    public function testDoesNotTripOverAnEntryWrittenBySomethingElse(): void
    {
        $pool = new ArrayAdapter();
        $item = $pool->getItem('atproto_did_document_' . md5(self::DID));
        $item->set('not a did document');
        $pool->save($item);

        self::assertNull(new Psr6DidDocumentCache($pool)->get(self::DID));
    }

    public function testDropsAnEntryOnceTheTtlHasPassed(): void
    {
        $cache = new Psr6DidDocumentCache(new ArrayAdapter(), ttl: -1);
        $cache->put(self::DID, ['id' => self::DID]);

        self::assertNull($cache->get(self::DID));
    }

    public function testKeepsDocumentsForDifferentDidsApart(): void
    {
        $cache = new Psr6DidDocumentCache(new ArrayAdapter());
        $cache->put(self::DID, ['id' => self::DID]);
        $cache->put('did:web:feed.test', ['id' => 'did:web:feed.test']);

        self::assertSame(['id' => self::DID], $cache->get(self::DID)['document'] ?? null);
        self::assertSame(['id' => 'did:web:feed.test'], $cache->get('did:web:feed.test')['document'] ?? null);
    }
}
