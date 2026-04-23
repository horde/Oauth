<?php

declare(strict_types=1);

/**
 * Copyright 2008-2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\V10a\Client;

use Horde\OAuth\Exception\TokenRequestFailedException;
use Horde\OAuth\V10a\Request\SignedRequest;
use Horde\OAuth\V10a\Signature\SignatureMethod;
use Horde\OAuth\V10a\Util\NonceGenerator;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

final class OAuth1Client
{
    public function __construct(
        private readonly ConsumerCredentials $consumer,
        private readonly ProviderEndpoints $endpoints,
        private readonly SignatureMethod $signatureMethod,
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
    ) {}

    /**
     * @param array<string, string> $extraParams
     */
    public function getRequestToken(string $callbackUrl, array $extraParams = []): Token
    {
        $params = array_merge($extraParams, [
            'oauth_consumer_key' => $this->consumer->key,
            'oauth_callback' => $callbackUrl,
            'oauth_version' => '1.0',
            'oauth_nonce' => NonceGenerator::generate(),
            'oauth_timestamp' => (string) time(),
        ]);

        $signed = new SignedRequest($this->endpoints->requestTokenUrl, $params);
        $signed->sign($this->signatureMethod, $this->consumer->secret, '');

        $body = $this->post($this->endpoints->requestTokenUrl, $signed->toFormBody());

        return Token::fromResponseBody($body);
    }

    public function getAuthorizationUrl(Token $requestToken, string $callbackUrl): string
    {
        return $this->endpoints->authorizeUrl
            . '?oauth_token=' . urlencode($requestToken->key)
            . '&oauth_callback=' . urlencode($callbackUrl);
    }

    /**
     * @param array<string, string> $extraParams
     */
    public function getAccessToken(Token $requestToken, string $oauthVerifier, array $extraParams = []): Token
    {
        $params = array_merge($extraParams, [
            'oauth_consumer_key' => $this->consumer->key,
            'oauth_token' => $requestToken->key,
            'oauth_verifier' => $oauthVerifier,
            'oauth_version' => '1.0',
            'oauth_nonce' => NonceGenerator::generate(),
            'oauth_timestamp' => (string) time(),
        ]);

        $signed = new SignedRequest($this->endpoints->accessTokenUrl, $params);
        $signed->sign($this->signatureMethod, $this->consumer->secret, $requestToken->secret);

        $body = $this->post($this->endpoints->accessTokenUrl, $signed->toFormBody());

        return Token::fromResponseBody($body);
    }

    private function post(string $url, string $formBody): string
    {
        $request = $this->requestFactory->createRequest('POST', $url)
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withBody($this->streamFactory->createStream($formBody));

        $response = $this->httpClient->sendRequest($request);
        $responseBody = (string) $response->getBody();

        if ($response->getStatusCode() !== 200) {
            throw new TokenRequestFailedException(
                'Token endpoint returned HTTP ' . $response->getStatusCode() . ': ' . $responseBody,
                $response->getStatusCode(),
            );
        }

        return $responseBody;
    }
}
