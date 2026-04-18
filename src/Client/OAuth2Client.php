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

namespace Horde\Oauth\Client;

use Horde\Oauth\Exception\OAuthException;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

final class OAuth2Client
{
    public function __construct(
        private readonly ProviderConfig $provider,
        private readonly string $clientId,
        private readonly ?string $clientSecret,
        private readonly string $redirectUri,
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
    ) {}

    /**
     * @param string[] $scopes
     * @param array<string, string> $extraParams
     */
    public function getAuthorizationUrl(
        array $scopes = [],
        ?string $state = null,
        ?string $nonce = null,
        ?string $codeChallenge = null,
        ?string $codeChallengeMethod = null,
        array $extraParams = [],
    ): string {
        $params = [
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
        ];

        if ($scopes !== []) {
            $params['scope'] = implode(' ', $scopes);
        }
        if ($state !== null) {
            $params['state'] = $state;
        }
        if ($nonce !== null) {
            $params['nonce'] = $nonce;
        }
        if ($codeChallenge !== null) {
            $params['code_challenge'] = $codeChallenge;
            $params['code_challenge_method'] = $codeChallengeMethod ?? 'S256';
        }

        $params = array_merge($params, $extraParams);

        return $this->provider->authorizationEndpoint . '?' . http_build_query($params);
    }

    public function exchangeCode(string $code, ?string $codeVerifier = null): TokenSet
    {
        $params = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri,
        ];

        if ($codeVerifier !== null) {
            $params['code_verifier'] = $codeVerifier;
        }

        if ($this->clientSecret === null) {
            $params['client_id'] = $this->clientId;
        }

        return $this->tokenRequest($params);
    }

    public function refreshToken(string $refreshToken, ?string $scope = null): TokenSet
    {
        $refresher = new TokenRefresher(
            $this->httpClient,
            $this->requestFactory,
            $this->streamFactory,
            $this->provider->tokenEndpoint,
            $this->clientId,
            $this->clientSecret,
        );

        return $refresher->refresh($refreshToken, $scope);
    }

    /**
     * @return array<string, mixed>
     */
    public function fetchUserinfo(string $accessToken): array
    {
        if ($this->provider->userinfoEndpoint === null) {
            throw new OAuthException('invalid_request', 'Provider does not support a userinfo endpoint');
        }

        $request = $this->requestFactory->createRequest('GET', $this->provider->userinfoEndpoint)
            ->withHeader('Authorization', 'Bearer ' . $accessToken)
            ->withHeader('Accept', 'application/json');

        $response = $this->httpClient->sendRequest($request);
        $data = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);

        if (!is_array($data)) {
            throw new OAuthException('invalid_request', 'Userinfo endpoint returned invalid response');
        }

        return $data;
    }

    /**
     * @param array<string, string> $params
     */
    private function tokenRequest(array $params): TokenSet
    {
        $body = $this->streamFactory->createStream(http_build_query($params));

        $request = $this->requestFactory->createRequest('POST', $this->provider->tokenEndpoint)
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
                $data['error_description'] ?? 'Token request failed',
            );
        }

        return TokenSet::fromArray($data);
    }
}
