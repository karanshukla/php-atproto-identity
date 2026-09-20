<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity;

final class NullDidDocumentCache implements DidDocumentCache
{
    public function get(string $did): ?array
    {
        return null;
    }

    public function put(string $did, array $document): void {}
}
