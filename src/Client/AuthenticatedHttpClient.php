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

namespace Horde\OAuth\Client;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

final class AuthenticatedHttpClient implements ClientInterface
{
    private TokenSet $tokenSet;
    private bool $wasRefreshed = false;

    public function __construct(
        private readonly ClientInterface $inner,
        TokenSet $tokenSet,
        private readonly ?TokenRefresher $refresher = null,
    ) {
        $this->tokenSet = $tokenSet;
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->wasRefreshed = false;

        $request = $request->withHeader('Authorization', 'Bearer ' . $this->tokenSet->accessToken);
        $response = $this->inner->sendRequest($request);

        if ($response->getStatusCode() !== 401) {
            return $response;
        }

        if ($this->refresher === null || $this->tokenSet->refreshToken === null) {
            return $response;
        }

        $refreshed = $this->refresher->refresh($this->tokenSet->refreshToken, $this->tokenSet->scope);

        if ($refreshed->refreshToken === null && $this->tokenSet->refreshToken !== null) {
            $refreshed = new TokenSet(
                accessToken: $refreshed->accessToken,
                tokenType: $refreshed->tokenType,
                expiresIn: $refreshed->expiresIn,
                refreshToken: $this->tokenSet->refreshToken,
                scope: $refreshed->scope ?? $this->tokenSet->scope,
                idToken: $refreshed->idToken,
                receivedAt: $refreshed->receivedAt,
            );
        }

        $this->tokenSet = $refreshed;
        $this->wasRefreshed = true;

        $request = $request->withHeader('Authorization', 'Bearer ' . $this->tokenSet->accessToken);
        return $this->inner->sendRequest($request);
    }

    public function getTokenSet(): TokenSet
    {
        return $this->tokenSet;
    }

    public function wasRefreshed(): bool
    {
        return $this->wasRefreshed;
    }
}
