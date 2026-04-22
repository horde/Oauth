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

namespace Horde\OAuth\Server\Middleware;

use Horde\Jwt\Exception\ExpiredTokenException;
use Horde\Jwt\Exception\InvalidTokenException;
use Horde\Jwt\TokenDecoder;
use Horde\Jwt\Verifier\VerifierInterface;
use Horde\OAuth\Server\Repository\AccessTokenRepository;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class BearerTokenMiddleware implements MiddlewareInterface
{
    /**
     * @param array<string, mixed> $verifyOptions
     */
    public function __construct(
        private readonly TokenDecoder $decoder,
        private readonly VerifierInterface $verifier,
        private readonly AccessTokenRepository $tokenRepository,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly StreamFactoryInterface $streamFactory,
        private readonly bool $required = true,
        private readonly array $verifyOptions = [],
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $header = $request->getHeaderLine('Authorization');
        $token = null;

        if (str_starts_with($header, 'Bearer ')) {
            $token = substr($header, 7);
        }

        if ($token === null || $token === '') {
            if ($this->required) {
                return $this->unauthorized('No access token provided');
            }
            return $handler->handle($request);
        }

        try {
            $verified = $this->decoder->decode($token, $this->verifier, $this->verifyOptions);
        } catch (ExpiredTokenException) {
            return $this->unauthorized('Access token has expired', 'invalid_token');
        } catch (InvalidTokenException) {
            return $this->unauthorized('Access token is invalid', 'invalid_token');
        }

        $jti = $verified->getClaim('jti');
        if (is_string($jti) && $this->tokenRepository->isRevoked($jti)) {
            return $this->unauthorized('Access token has been revoked', 'invalid_token');
        }

        $request = $request
            ->withAttribute('oauth_access_token', $verified)
            ->withAttribute('oauth_client_id', $verified->getClaim('client_id'))
            ->withAttribute('oauth_user_id', $verified->getSubject())
            ->withAttribute('oauth_scopes', $verified->getClaim('scope', ''));

        return $handler->handle($request);
    }

    private function unauthorized(string $description, string $error = ''): ResponseInterface
    {
        $wwwAuth = 'Bearer';
        if ($error !== '') {
            $wwwAuth .= " error=\"{$error}\", error_description=\"{$description}\"";
        }

        $body = json_encode(array_filter([
            'error' => $error ?: 'invalid_request',
            'error_description' => $description,
        ]), JSON_THROW_ON_ERROR);

        return $this->responseFactory->createResponse(401)
            ->withHeader('WWW-Authenticate', $wwwAuth)
            ->withHeader('Content-Type', 'application/json;charset=UTF-8')
            ->withBody($this->streamFactory->createStream($body));
    }
}
