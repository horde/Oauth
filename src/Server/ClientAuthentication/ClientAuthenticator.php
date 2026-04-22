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

namespace Horde\OAuth\Server\ClientAuthentication;

use Psr\Http\Message\ServerRequestInterface;

interface ClientAuthenticator
{
    /**
     * @return array{0: string, 1: ?string}|null [clientId, clientSecret] or null if not applicable
     */
    public function authenticate(ServerRequestInterface $request): ?array;

    public function getMethod(): string;
}
