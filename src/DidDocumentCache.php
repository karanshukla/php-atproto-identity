<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity;

/**
 * Storage for resolved DID documents.
 *
 * Not PSR-6 or PSR-16: both report validity, and {@see HttpDidDocumentResolver}
 * needs age. {@see Psr6DidDocumentCache} adapts a pool to it.
 */
interface DidDocumentCache
{
    /**
     * @return array{document: array<string, mixed>, age: int}|null age is in seconds
     */
    public function get(string $did): ?array;

    /** @param array<string, mixed> $document */
    public function put(string $did, array $document): void;
}
