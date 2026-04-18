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

namespace Horde\Oauth\Oidc\Handler;

use Horde\Oauth\Oidc\ClaimsMapper;
use Horde\Oauth\Oidc\ScopeClaimsMapping;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class UserinfoEndpoint implements RequestHandlerInterface
{
    public function __construct(
        private readonly ClaimsMapper $claimsMapper,
        private readonly ScopeClaimsMapping $scopeMapping,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly StreamFactoryInterface $streamFactory,
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $identityId = $request->getAttribute('oauth_user_id');
        $scopeString = $request->getAttribute('oauth_scopes', '');

        if (!is_string($identityId) || $identityId === '') {
            $body = $this->streamFactory->createStream(json_encode([
                'error' => 'invalid_token',
                'error_description' => 'Access token required',
            ], JSON_THROW_ON_ERROR));

            return $this->responseFactory->createResponse(401)
                ->withHeader('WWW-Authenticate', 'Bearer')
                ->withHeader('Content-Type', 'application/json;charset=UTF-8')
                ->withBody($body);
        }

        $scopes = is_string($scopeString) ? array_filter(explode(' ', $scopeString)) : [];
        $claimNames = $this->scopeMapping->getClaimsForScopes($scopes);
        $claims = $this->claimsMapper->getClaims($identityId, $claimNames);

        $claims['sub'] = $identityId;

        $json = json_encode($claims, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $body = $this->streamFactory->createStream($json);

        return $this->responseFactory->createResponse(200)
            ->withHeader('Content-Type', 'application/json;charset=UTF-8')
            ->withBody($body);
    }
}
