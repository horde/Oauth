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

final class TokenRequestFailedException extends OAuthException
{
    public function __construct(string $description = 'Token request failed', int $httpStatusCode = 400, ?Throwable $previous = null)
    {
        parent::__construct('token_request_failed', $description, '', $httpStatusCode, $previous);
    }
}
