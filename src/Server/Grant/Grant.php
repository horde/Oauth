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

namespace Horde\OAuth\Server\Grant;

use Horde\OAuth\Exception\OAuthException;
use Horde\OAuth\Server\Entity\Client;
use Psr\Http\Message\ServerRequestInterface;

interface Grant
{
    public function getIdentifier(): string;

    /**
     * @return array<string, mixed>
     * @throws OAuthException
     */
    public function respondToTokenRequest(ServerRequestInterface $request, Client $client): array;
}
