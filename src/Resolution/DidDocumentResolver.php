<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity\Resolution;

use KaranShukla\PhpAtprotoIdentity\IdentityException;

interface DidDocumentResolver
{
    /**
     * @return array<string, mixed> the DID document
     *
     * @throws IdentityException
     */
    public function resolve(string $did, bool $forceRefresh = false): array;
}
