<?php

declare(strict_types=1);

namespace KaranShukla\PhpAtprotoIdentity;

use RuntimeException;

/**
 * Raised whenever an identity cannot be resolved or a published key cannot be
 * read.
 */
class IdentityException extends RuntimeException {}
