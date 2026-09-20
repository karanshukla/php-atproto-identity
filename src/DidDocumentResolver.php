<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity;

interface DidDocumentResolver
{
    /**
     * @return array<string, mixed> the DID document
     *
     * @throws IdentityException
     */
    public function resolve(string $did, bool $forceRefresh = false): array;
}
