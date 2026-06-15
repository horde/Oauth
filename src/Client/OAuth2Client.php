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
            'client_id' => $this->clientId,
        ];

        if ($codeVerifier !== null) {
            $params['code_verifier'] = $codeVerifier;
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
     * Build an authorization URL for incremental consent.
     *
     * Merges the user's currently granted scopes with the additionally
     * needed scopes. If all needed scopes are already granted, returns
     * a result with consentNeeded = false.
     *
     * Provider-specific behavior:
     * - Google: pass ['include_granted_scopes' => 'true'] via $extraParams
     * - GitHub: replaces full scope set (no native incremental, but
     *   merge-and-send works — user re-consents to the full set)
     * - Mastodon: reissues token with new scope set
     *
     * @param array<string, string> $extraParams
     */
    public function getIncrementalConsentUrl(
        ScopeSet $currentScopes,
        ScopeSet $neededScopes,
        ?string $state = null,
        ?string $codeChallenge = null,
        ?string $codeChallengeMethod = null,
        array $extraParams = [],
    ): IncrementalConsentResult {
        $merged = $currentScopes->union($neededScopes);

        if ($currentScopes->hasAll($neededScopes)) {
            return new IncrementalConsentResult(
                authorizationUrl: '',
                consentNeeded: false,
                mergedScopes: $merged,
            );
        }

        $url = $this->getAuthorizationUrl(
            scopes: $merged->toArray(),
            state: $state,
            codeChallenge: $codeChallenge,
            codeChallengeMethod: $codeChallengeMethod,
            extraParams: $extraParams,
        );

        return new IncrementalConsentResult(
            authorizationUrl: $url,
            consentNeeded: true,
            mergedScopes: $merged,
        );
    }

    /**
     * @param array<string, string> $params
     */
    private function tokenRequest(array $params): TokenSet
    {
        if ($this->clientSecret !== null) {
            $useBasic = in_array('client_secret_basic', $this->provider->tokenEndpointAuthMethodsSupported, true)
                && !in_array('client_secret_post', $this->provider->tokenEndpointAuthMethodsSupported, true);

            if (!$useBasic) {
                $params['client_secret'] = $this->clientSecret;
            }
        }

        $body = $this->streamFactory->createStream(http_build_query($params));

        $request = $this->requestFactory->createRequest('POST', $this->provider->tokenEndpoint)
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withHeader('Accept', 'application/json')
            ->withBody($body);

        if ($this->clientSecret !== null && ($useBasic ?? false)) {
            $credentials = base64_encode(urlencode($this->clientId) . ':' . urlencode($this->clientSecret));
            $request = $request->withHeader('Authorization', 'Basic ' . $credentials);
        }

        $response = $this->httpClient->sendRequest($request);
        $responseBody = (string) $response->getBody();
        $data = json_decode($responseBody, true, 512);
        if (!is_array($data)) {
            // Fallback: some providers (e.g. GitHub) may return form-urlencoded
            parse_str($responseBody, $data);
        }

        if (!is_array($data) || $data === []) {
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

    /**
     * Revoke a token at the provider's revocation endpoint (RFC 7009).
     *
     * @param string $token          The token to revoke (access or refresh).
     * @param string $tokenTypeHint  'access_token' or 'refresh_token'.
     * @throws OAuthException        If the provider has no revocation endpoint
     *                               or the request fails.
     */
    public function revokeToken(string $token, string $tokenTypeHint = 'access_token'): void
    {
        if ($this->provider->revocationEndpoint === null) {
            throw new OAuthException('invalid_request', 'Provider does not support a revocation endpoint');
        }

        $params = [
            'token'           => $token,
            'token_type_hint' => $tokenTypeHint,
            'client_id'       => $this->clientId,
        ];

        $useBasic = false;
        if ($this->clientSecret !== null) {
            $useBasic = in_array('client_secret_basic', $this->provider->tokenEndpointAuthMethodsSupported, true)
                && !in_array('client_secret_post', $this->provider->tokenEndpointAuthMethodsSupported, true);

            if (!$useBasic) {
                $params['client_secret'] = $this->clientSecret;
            }
        }

        $body = $this->streamFactory->createStream(http_build_query($params));

        $request = $this->requestFactory->createRequest('POST', $this->provider->revocationEndpoint)
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withHeader('Accept', 'application/json')
            ->withBody($body);

        if ($this->clientSecret !== null && $useBasic) {
            $credentials = base64_encode(urlencode($this->clientId) . ':' . urlencode($this->clientSecret));
            $request = $request->withHeader('Authorization', 'Basic ' . $credentials);
        }

        $response = $this->httpClient->sendRequest($request);

        if ($response->getStatusCode() >= 400) {
            $data = json_decode((string) $response->getBody(), true) ?? [];
            throw new OAuthException(
                $data['error'] ?? 'server_error',
                $data['error_description'] ?? 'Token revocation failed',
            );
        }
    }
}
