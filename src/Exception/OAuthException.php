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

use RuntimeException;
use Throwable;

class OAuthException extends RuntimeException
{
    public function __construct(
        private readonly string $error,
        string $errorDescription = '',
        private readonly string $errorUri = '',
        private readonly int $httpStatusCode = 400,
        ?Throwable $previous = null,
    ) {
        parent::__construct($errorDescription, 0, $previous);
    }

    public function getError(): string
    {
        return $this->error;
    }

    public function getErrorDescription(): string
    {
        return $this->getMessage();
    }

    public function getErrorUri(): string
    {
        return $this->errorUri;
    }

    public function getHttpStatusCode(): int
    {
        return $this->httpStatusCode;
    }
}
