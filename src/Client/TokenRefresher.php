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

use Horde\OAuth\Exception\OAuthException;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

final class TokenRefresher
{
    public function __construct(
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
        private readonly string $tokenEndpoint,
        private readonly string $clientId,
        private readonly ?string $clientSecret = null,
    ) {}

    public function refresh(string $refreshToken, ?string $scope = null): TokenSet
    {
        $params = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
        ];

        if ($scope !== null) {
            $params['scope'] = $scope;
        }

        if ($this->clientSecret === null) {
            $params['client_id'] = $this->clientId;
        }

        $body = $this->streamFactory->createStream(http_build_query($params));

        $request = $this->requestFactory->createRequest('POST', $this->tokenEndpoint)
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withBody($body);

        if ($this->clientSecret !== null) {
            $credentials = base64_encode(urlencode($this->clientId) . ':' . urlencode($this->clientSecret));
            $request = $request->withHeader('Authorization', 'Basic ' . $credentials);
        }

        $response = $this->httpClient->sendRequest($request);
        $data = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);

        if (!is_array($data)) {
            throw new OAuthException('invalid_request', 'Token endpoint returned invalid response');
        }

        if ($response->getStatusCode() !== 200) {
            throw new OAuthException(
                $data['error'] ?? 'server_error',
                $data['error_description'] ?? 'Token refresh failed',
            );
        }

        return TokenSet::fromArray($data);
    }
}
