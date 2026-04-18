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

namespace Horde\Oauth\Server\ClientAuthentication;

use Psr\Http\Message\ServerRequestInterface;

final class ClientSecretPost implements ClientAuthenticator
{
    public function getMethod(): string
    {
        return 'client_secret_post';
    }

    public function authenticate(ServerRequestInterface $request): ?array
    {
        $body = $request->getParsedBody();
        if (!is_array($body)) {
            return null;
        }

        $clientId = $body['client_id'] ?? null;
        $clientSecret = $body['client_secret'] ?? null;

        if (!is_string($clientId) || $clientId === '') {
            return null;
        }

        return [$clientId, is_string($clientSecret) ? $clientSecret : null];
    }
}
