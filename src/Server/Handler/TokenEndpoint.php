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

namespace Horde\Oauth\Server\Handler;

use Horde\Oauth\ErrorResponse;
use Horde\Oauth\Exception\OAuthException;
use Horde\Oauth\Exception\InvalidRequestException;
use Horde\Oauth\Exception\UnsupportedGrantTypeException;
use Horde\Oauth\Server\ClientAuthentication\ClientAuthenticatorChain;
use Horde\Oauth\Server\Grant\Grant;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class TokenEndpoint implements RequestHandlerInterface
{
    /** @var array<string, Grant> */
    private array $grants = [];

    public function __construct(
        private readonly ClientAuthenticatorChain $clientAuthenticator,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly StreamFactoryInterface $streamFactory,
        Grant ...$grants,
    ) {
        foreach ($grants as $grant) {
            $this->grants[$grant->getIdentifier()] = $grant;
        }
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            $body = (array) $request->getParsedBody();

            $grantType = $body['grant_type'] ?? null;
            if (!is_string($grantType) || $grantType === '') {
                throw new InvalidRequestException('Missing required parameter: grant_type');
            }

            $grant = $this->grants[$grantType] ?? null;
            if ($grant === null) {
                throw new UnsupportedGrantTypeException("Grant type '{$grantType}' is not supported");
            }

            $client = $this->clientAuthenticator->authenticateClientOrPublic($request);

            if (!$client->supportsGrantType($grantType)) {
                throw new UnsupportedGrantTypeException("Client is not authorized for grant type '{$grantType}'");
            }

            $result = $grant->respondToTokenRequest($request, $client);

            $filtered = array_filter($result, static fn(string $key) => !str_starts_with($key, '_'), ARRAY_FILTER_USE_KEY);

            $json = json_encode($filtered, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            $responseBody = $this->streamFactory->createStream($json);

            return $this->responseFactory->createResponse(200)
                ->withHeader('Content-Type', 'application/json;charset=UTF-8')
                ->withHeader('Cache-Control', 'no-store')
                ->withHeader('Pragma', 'no-cache')
                ->withBody($responseBody);
        } catch (OAuthException $e) {
            return ErrorResponse::toResponse($e, $this->responseFactory, $this->streamFactory);
        }
    }
}
