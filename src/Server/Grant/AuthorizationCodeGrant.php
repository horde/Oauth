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

use Horde\OAuth\Exception\InvalidGrantException;
use Horde\OAuth\Exception\InvalidRequestException;
use Horde\OAuth\Server\Entity\Client;
use Horde\OAuth\Server\Entity\Scope;
use Horde\OAuth\Server\Pkce\PkceVerifier;
use Horde\OAuth\Server\Repository\AuthorizationCodeRepository;
use Horde\OAuth\Server\Repository\ScopeRepository;
use Horde\OAuth\Server\Token\AccessTokenIssuer;
use Horde\OAuth\Server\Token\RefreshTokenIssuer;
use Psr\Http\Message\ServerRequestInterface;

final class AuthorizationCodeGrant implements Grant
{
    public function __construct(
        private readonly AuthorizationCodeRepository $authCodeRepository,
        private readonly AccessTokenIssuer $accessTokenIssuer,
        private readonly ?RefreshTokenIssuer $refreshTokenIssuer,
        private readonly ScopeRepository $scopeRepository,
    ) {}

    public function getIdentifier(): string
    {
        return 'authorization_code';
    }

    public function respondToTokenRequest(ServerRequestInterface $request, Client $client): array
    {
        $body = (array) $request->getParsedBody();

        $code = $body['code'] ?? null;
        if (!is_string($code) || $code === '') {
            throw new InvalidRequestException('Missing required parameter: code');
        }

        $redirectUri = $body['redirect_uri'] ?? null;

        $authCode = $this->authCodeRepository->findByCode($code);
        if ($authCode === null) {
            throw new InvalidGrantException('Authorization code is invalid');
        }

        if ($authCode->isUsed()) {
            throw new InvalidGrantException('Authorization code has already been used');
        }

        if ($authCode->isExpired()) {
            throw new InvalidGrantException('Authorization code has expired');
        }

        if ($authCode->clientId !== $client->clientId) {
            throw new InvalidGrantException('Authorization code was not issued to this client');
        }

        if ($authCode->redirectUri !== '' && $authCode->redirectUri !== $redirectUri) {
            throw new InvalidGrantException('Redirect URI mismatch');
        }

        if ($authCode->codeChallenge !== null) {
            $codeVerifier = $body['code_verifier'] ?? null;
            if (!is_string($codeVerifier) || $codeVerifier === '') {
                throw new InvalidRequestException('Missing required parameter: code_verifier');
            }
            $method = $authCode->codeChallengeMethod ?? 'plain';
            if (!PkceVerifier::verify($codeVerifier, $authCode->codeChallenge, $method)) {
                throw new InvalidGrantException('PKCE verification failed');
            }
        }

        $this->authCodeRepository->markUsed($code);

        $scopes = Scope::fromSpaceSeparated($authCode->scope);
        $scopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client, $authCode->identityId);

        $response = $this->accessTokenIssuer->issue($client, $authCode->identityId, $scopes);

        if ($this->refreshTokenIssuer !== null) {
            $jti = $response['_jti'];
            $response['refresh_token'] = $this->refreshTokenIssuer->issue($jti, $client, $authCode->identityId, $scopes);
        }

        unset($response['_jti']);

        $response['_identity_id'] = $authCode->identityId;
        $response['_nonce'] = $authCode->nonce;

        return $response;
    }
}
