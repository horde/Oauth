<?php

declare(strict_types=1);

/**
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 *
 * @author   Ralf Lang <ralf.lang@ralf-lang.de>
 */

namespace Horde\Oauth\Exception;

final class InvalidScopeException extends OAuthException
{
    public function __construct(
        string $errorDescription = '',
        string $errorUri = '',
        ?\Throwable $previous = null,
    ) {
        parent::__construct('invalid_scope', $errorDescription, $errorUri, 400, $previous);
    }
}
