<?php

declare(strict_types=1);

/**
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\Exception;

use Throwable;

final class InvalidSignatureException extends OAuthException
{
    public function __construct(string $description = 'Signature verification failed', ?Throwable $previous = null)
    {
        parent::__construct('invalid_signature', $description, '', 401, $previous);
    }
}
