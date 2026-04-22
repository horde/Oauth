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

final class RevocationEndpoint implements RequestHandlerInterface
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
        $token = $body['token'] ?? null;

        if (!is_string($token) || $token === '') {
            return $this->responseFactory->createResponse(200);
        }

        $hint = $body['token_type_hint'] ?? null;

        if ($hint === 'refresh_token') {
            $this->refreshTokenRepository->revoke($token);
        } elseif ($hint === 'access_token') {
            $this->accessTokenRepository->revoke($token);
        } else {
            $this->accessTokenRepository->revoke($token);
            $this->refreshTokenRepository->revoke($token);
        }

        return $this->responseFactory->createResponse(200);
    }
}
