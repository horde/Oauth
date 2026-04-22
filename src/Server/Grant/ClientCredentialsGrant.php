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

use Horde\OAuth\Server\Entity\Client;
use Horde\OAuth\Server\Entity\Scope;
use Horde\OAuth\Server\Repository\ScopeRepository;
use Horde\OAuth\Server\Token\AccessTokenIssuer;
use Psr\Http\Message\ServerRequestInterface;

final class ClientCredentialsGrant implements Grant
{
    public function __construct(
        private readonly AccessTokenIssuer $accessTokenIssuer,
        private readonly ScopeRepository $scopeRepository,
    ) {}

    public function getIdentifier(): string
    {
        return 'client_credentials';
    }

    public function respondToTokenRequest(ServerRequestInterface $request, Client $client): array
    {
        $body = (array) $request->getParsedBody();

        $requestedScope = $body['scope'] ?? '';
        $scopes = is_string($requestedScope) ? Scope::fromSpaceSeparated($requestedScope) : [];
        $scopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client);

        $response = $this->accessTokenIssuer->issue($client, null, $scopes);

        unset($response['_jti']);

        return $response;
    }
}
