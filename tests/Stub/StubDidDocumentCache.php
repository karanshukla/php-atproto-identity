<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Tests\Stub;

use KaranShukla\PhpAtprotoIdentity\Resolution\Cache\DidDocumentCache;

/**
 * An in-memory cache whose entries have a settable age, so a test can put a
 * document on either side of a freshness bound without waiting.
 *
 * @internal
 */
final class StubDidDocumentCache implements DidDocumentCache
{
    public int $writes = 0;

    /** @var array<string, array{document: array<string, mixed>, age: int}> */
    private array $entries = [];

    /** @param array<string, mixed> $document */
    public function seed(string $did, array $document, int $age): void
    {
        $this->entries[$did] = ['document' => $document, 'age' => $age];
    }

    public function get(string $did): ?array
    {
        return $this->entries[$did] ?? null;
    }

    public function put(string $did, array $document): void
    {
        $this->writes++;
        $this->entries[$did] = ['document' => $document, 'age' => 0];
    }
}
