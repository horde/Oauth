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

namespace Horde\Oauth\Server\Grant;

use Horde\Oauth\Exception\InvalidGrantException;
use Horde\Oauth\Exception\InvalidRequestException;
use Horde\Oauth\Server\Entity\Client;
use Horde\Oauth\Server\Entity\Scope;
use Horde\Oauth\Server\Repository\AccessTokenRepository;
use Horde\Oauth\Server\Repository\RefreshTokenRepository;
use Horde\Oauth\Server\Repository\ScopeRepository;
use Horde\Oauth\Server\Token\AccessTokenIssuer;
use Horde\Oauth\Server\Token\RefreshTokenIssuer;
use Psr\Http\Message\ServerRequestInterface;

final class RefreshTokenGrant implements Grant
{
    public function __construct(
        private readonly RefreshTokenRepository $refreshTokenRepository,
        private readonly AccessTokenRepository $accessTokenRepository,
        private readonly AccessTokenIssuer $accessTokenIssuer,
        private readonly ?RefreshTokenIssuer $refreshTokenIssuer,
        private readonly ScopeRepository $scopeRepository,
    ) {}

    public function getIdentifier(): string
    {
        return 'refresh_token';
    }

    public function respondToTokenRequest(ServerRequestInterface $request, Client $client): array
    {
        $body = (array) $request->getParsedBody();

        $refreshTokenId = $body['refresh_token'] ?? null;
        if (!is_string($refreshTokenId) || $refreshTokenId === '') {
            throw new InvalidRequestException('Missing required parameter: refresh_token');
        }

        $refreshToken = $this->refreshTokenRepository->findById($refreshTokenId);
        if ($refreshToken === null) {
            throw new InvalidGrantException('Refresh token is invalid');
        }

        if ($refreshToken->isRevoked()) {
            throw new InvalidGrantException('Refresh token has been revoked');
        }

        if ($refreshToken->isExpired()) {
            throw new InvalidGrantException('Refresh token has expired');
        }

        if ($refreshToken->clientId !== $client->clientId) {
            throw new InvalidGrantException('Refresh token was not issued to this client');
        }

        $requestedScope = $body['scope'] ?? '';
        $scopes = is_string($requestedScope) && $requestedScope !== ''
            ? Scope::fromSpaceSeparated($requestedScope)
            : Scope::fromSpaceSeparated($refreshToken->scope);

        if ($requestedScope !== '') {
            $originalScopes = array_map(
                static fn(Scope $s) => $s->identifier,
                Scope::fromSpaceSeparated($refreshToken->scope),
            );
            foreach ($scopes as $scope) {
                if (!in_array($scope->identifier, $originalScopes, true)) {
                    throw new InvalidGrantException('Requested scope exceeds original grant');
                }
            }
        }

        $scopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client, $refreshToken->identityId);

        $this->accessTokenRepository->revoke($refreshToken->accessTokenId);
        $this->refreshTokenRepository->revoke($refreshTokenId);

        $response = $this->accessTokenIssuer->issue($client, $refreshToken->identityId, $scopes);

        if ($this->refreshTokenIssuer !== null) {
            $jti = $response['_jti'];
            $response['refresh_token'] = $this->refreshTokenIssuer->issue($jti, $client, $refreshToken->identityId, $scopes);
        }

        unset($response['_jti']);

        return $response;
    }
}
