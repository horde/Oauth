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

final class ClientSecretBasic implements ClientAuthenticator
{
    public function getMethod(): string
    {
        return 'client_secret_basic';
    }

    public function authenticate(ServerRequestInterface $request): ?array
    {
        $header = $request->getHeaderLine('Authorization');
        if ($header === '' || !str_starts_with($header, 'Basic ')) {
            return null;
        }

        $decoded = base64_decode(substr($header, 6), true);
        if ($decoded === false || !str_contains($decoded, ':')) {
            return null;
        }

        [$clientId, $clientSecret] = explode(':', $decoded, 2);

        return [urldecode($clientId), urldecode($clientSecret)];
    }
}
