<?php

declare(strict_types=1);

/**
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\Test\V10a\Client;

use Horde\OAuth\Exception\TokenRequestFailedException;
use Horde\OAuth\V10a\Client\ConsumerCredentials;
use Horde\OAuth\V10a\Client\OAuth1Client;
use Horde\OAuth\V10a\Client\ProviderEndpoints;
use Horde\OAuth\V10a\Client\Token;
use Horde\OAuth\V10a\Signature\HmacSha1;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;

#[CoversClass(OAuth1Client::class)]
final class OAuth1ClientTest extends TestCase
{
    private ConsumerCredentials $consumer;
    private ProviderEndpoints $endpoints;

    protected function setUp(): void
    {
        $this->consumer = new ConsumerCredentials('consumer-key', 'consumer-secret');
        $this->endpoints = new ProviderEndpoints(
            'https://provider.example/request_token',
            'https://provider.example/authorize',
            'https://provider.example/access_token',
        );
    }

    public function testGetRequestToken(): void
    {
        $responseBody = 'oauth_token=req-tok&oauth_token_secret=req-secret&oauth_callback_confirmed=true';

        [$httpClient, $requestFactory, $streamFactory] = $this->createMockHttp(200, $responseBody);

        $client = new OAuth1Client(
            $this->consumer,
            $this->endpoints,
            new HmacSha1(),
            $httpClient,
            $requestFactory,
            $streamFactory,
        );

        $token = $client->getRequestToken('https://app.example/callback');

        self::assertSame('req-tok', $token->key);
        self::assertSame('req-secret', $token->secret);
    }

    public function testGetRequestTokenThrowsOnError(): void
    {
        [$httpClient, $requestFactory, $streamFactory] = $this->createMockHttp(401, 'Unauthorized');

        $client = new OAuth1Client(
            $this->consumer,
            $this->endpoints,
            new HmacSha1(),
            $httpClient,
            $requestFactory,
            $streamFactory,
        );

        $this->expectException(TokenRequestFailedException::class);
        $client->getRequestToken('https://app.example/callback');
    }

    public function testGetAuthorizationUrl(): void
    {
        [$httpClient, $requestFactory, $streamFactory] = $this->createMockHttp(200, '');

        $client = new OAuth1Client(
            $this->consumer,
            $this->endpoints,
            new HmacSha1(),
            $httpClient,
            $requestFactory,
            $streamFactory,
        );

        $requestToken = new Token('req-tok', 'req-secret');
        $url = $client->getAuthorizationUrl($requestToken, 'https://app.example/callback');

        self::assertStringStartsWith('https://provider.example/authorize?', $url);
        self::assertStringContainsString('oauth_token=req-tok', $url);
        self::assertStringContainsString('oauth_callback=' . urlencode('https://app.example/callback'), $url);
    }

    public function testGetAccessToken(): void
    {
        $responseBody = 'oauth_token=access-tok&oauth_token_secret=access-secret';

        [$httpClient, $requestFactory, $streamFactory] = $this->createMockHttp(200, $responseBody);

        $client = new OAuth1Client(
            $this->consumer,
            $this->endpoints,
            new HmacSha1(),
            $httpClient,
            $requestFactory,
            $streamFactory,
        );

        $requestToken = new Token('req-tok', 'req-secret');
        $token = $client->getAccessToken($requestToken, 'verifier-value');

        self::assertSame('access-tok', $token->key);
        self::assertSame('access-secret', $token->secret);
    }

    public function testGetAccessTokenThrowsOnError(): void
    {
        [$httpClient, $requestFactory, $streamFactory] = $this->createMockHttp(403, 'Forbidden');

        $client = new OAuth1Client(
            $this->consumer,
            $this->endpoints,
            new HmacSha1(),
            $httpClient,
            $requestFactory,
            $streamFactory,
        );

        $requestToken = new Token('req-tok', 'req-secret');

        $this->expectException(TokenRequestFailedException::class);
        $client->getAccessToken($requestToken, 'bad-verifier');
    }

    public function testGetRequestTokenSendsPostWithFormBody(): void
    {
        $capturedRequest = null;

        $stream = $this->createMock(StreamInterface::class);
        $stream->method('__toString')->willReturn('oauth_token=t&oauth_token_secret=s');

        $response = $this->createMock(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);
        $response->method('getBody')->willReturn($stream);

        $httpClient = $this->createMock(ClientInterface::class);
        $httpClient->method('sendRequest')->willReturnCallback(
            function (RequestInterface $request) use (&$capturedRequest, $response): ResponseInterface {
                $capturedRequest = $request;
                return $response;
            }
        );

        [$requestFactory, $streamFactory] = $this->createFactories();

        $client = new OAuth1Client(
            $this->consumer,
            $this->endpoints,
            new HmacSha1(),
            $httpClient,
            $requestFactory,
            $streamFactory,
        );

        $client->getRequestToken('https://app.example/cb');

        self::assertNotNull($capturedRequest);
        self::assertSame('POST', $capturedRequest->getMethod());
        self::assertSame('application/x-www-form-urlencoded', $capturedRequest->getHeaderLine('Content-Type'));
    }

    /**
     * @return array{ClientInterface, RequestFactoryInterface, StreamFactoryInterface}
     */
    private function createMockHttp(int $statusCode, string $body): array
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('__toString')->willReturn($body);

        $response = $this->createMock(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn($statusCode);
        $response->method('getBody')->willReturn($stream);

        $httpClient = $this->createMock(ClientInterface::class);
        $httpClient->method('sendRequest')->willReturn($response);

        [$requestFactory, $streamFactory] = $this->createFactories();

        return [$httpClient, $requestFactory, $streamFactory];
    }

    /**
     * @return array{RequestFactoryInterface, StreamFactoryInterface}
     */
    private function createFactories(): array
    {
        $uri = $this->createMock(UriInterface::class);
        $uri->method('__toString')->willReturn('');

        $mockRequest = $this->createMock(RequestInterface::class);
        $mockRequest->method('withHeader')->willReturnSelf();
        $mockRequest->method('withBody')->willReturnSelf();
        $mockRequest->method('getMethod')->willReturn('POST');
        $mockRequest->method('getHeaderLine')->willReturnCallback(function (string $name) {
            if (strtolower($name) === 'content-type') {
                return 'application/x-www-form-urlencoded';
            }
            return '';
        });
        $mockRequest->method('getUri')->willReturn($uri);

        $requestFactory = $this->createMock(RequestFactoryInterface::class);
        $requestFactory->method('createRequest')->willReturn($mockRequest);

        $mockStream = $this->createMock(StreamInterface::class);

        $streamFactory = $this->createMock(StreamFactoryInterface::class);
        $streamFactory->method('createStream')->willReturn($mockStream);

        return [$requestFactory, $streamFactory];
    }
}
