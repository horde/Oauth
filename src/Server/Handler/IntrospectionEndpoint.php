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

namespace Horde\OAuth\Server\Handler;

use Horde\OAuth\ErrorResponse;
use Horde\OAuth\Exception\OAuthException;
use Horde\OAuth\Server\ClientAuthentication\ClientAuthenticatorChain;
use Horde\OAuth\Server\Repository\AccessTokenRepository;
use Horde\OAuth\Server\Repository\RefreshTokenRepository;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class IntrospectionEndpoint implements RequestHandlerInterface
{
    public function __construct(
        private readonly ClientAuthenticatorChain $clientAuthenticator,
        private readonly AccessTokenRepository $accessTokenRepository,
        private readonly RefreshTokenRepository $refreshTokenRepository,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly StreamFactoryInterface $streamFactory,
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            $this->clientAuthenticator->authenticateClient($request);
        } catch (OAuthException $e) {
            return ErrorResponse::toResponse($e, $this->responseFactory, $this->streamFactory);
        }

        $body = (array) $request->getParsedBody();
        $tokenValue = $body['token'] ?? null;

        if (!is_string($tokenValue) || $tokenValue === '') {
            return $this->jsonResponse(['active' => false]);
        }

        $hint = $body['token_type_hint'] ?? null;

        if ($hint === 'refresh_token') {
            $refreshToken = $this->refreshTokenRepository->findById($tokenValue);
            if ($refreshToken !== null && !$refreshToken->isRevoked() && !$refreshToken->isExpired()) {
                return $this->jsonResponse([
                    'active' => true,
                    'scope' => $refreshToken->scope,
                    'client_id' => $refreshToken->clientId,
                    'sub' => $refreshToken->identityId,
                    'exp' => $refreshToken->expiresAt->getTimestamp(),
                    'token_type' => 'refresh_token',
                ]);
            }
        }

        $accessToken = $this->accessTokenRepository->findById($tokenValue);
        if ($accessToken !== null && !$accessToken->isRevoked() && !$accessToken->isExpired()) {
            return $this->jsonResponse([
                'active' => true,
                'scope' => $accessToken->scope,
                'client_id' => $accessToken->clientId,
                'sub' => $accessToken->identityId,
                'exp' => $accessToken->expiresAt->getTimestamp(),
                'token_type' => 'Bearer',
            ]);
        }

        return $this->jsonResponse(['active' => false]);
    }

    /**
     * @param array<string, mixed> $data
     */
    private function jsonResponse(array $data): ResponseInterface
    {
        $json = json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $body = $this->streamFactory->createStream($json);

        return $this->responseFactory->createResponse(200)
            ->withHeader('Content-Type', 'application/json;charset=UTF-8')
            ->withHeader('Cache-Control', 'no-store')
            ->withBody($body);
    }
}
