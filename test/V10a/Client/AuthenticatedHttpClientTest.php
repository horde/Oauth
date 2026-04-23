<?php

declare(strict_types=1);

/**
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\Test\V10a\Client;

use Horde\OAuth\V10a\Client\AuthenticatedHttpClient;
use Horde\OAuth\V10a\Client\ConsumerCredentials;
use Horde\OAuth\V10a\Client\Token;
use Horde\OAuth\V10a\Signature\HmacSha1;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;

#[CoversClass(AuthenticatedHttpClient::class)]
final class AuthenticatedHttpClientTest extends TestCase
{
    public function testSendRequestAddsAuthorizationHeader(): void
    {
        $capturedRequest = null;

        $response = $this->createMock(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);

        $inner = $this->createMock(ClientInterface::class);
        $inner->method('sendRequest')->willReturnCallback(
            function (RequestInterface $req) use (&$capturedRequest, $response): ResponseInterface {
                $capturedRequest = $req;
                return $response;
            }
        );

        $client = new AuthenticatedHttpClient(
            $inner,
            new ConsumerCredentials('ck', 'cs'),
            new Token('at', 'as'),
            new HmacSha1(),
        );

        $uri = $this->createMock(UriInterface::class);
        $uri->method('__toString')->willReturn('https://api.example.com/resource');

        $request = $this->createMock(RequestInterface::class);
        $request->method('getMethod')->willReturn('GET');
        $request->method('getUri')->willReturn($uri);

        $withHeaderRequest = $this->createMock(RequestInterface::class);
        $withHeaderRequest->method('getHeaderLine')->willReturnCallback(function (string $name) {
            if (strtolower($name) === 'authorization') {
                return 'OAuth oauth_consumer_key="ck"';
            }
            return '';
        });

        $request->method('withHeader')->willReturnCallback(
            function (string $name, $value) use (&$capturedRequest, $withHeaderRequest): RequestInterface {
                $capturedRequest = $withHeaderRequest;
                return $withHeaderRequest;
            }
        );

        $client->sendRequest($request);

        self::assertNotNull($capturedRequest);
    }

    public function testSendRequestIncludesOAuthParams(): void
    {
        $authHeader = null;

        $response = $this->createMock(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);

        $inner = $this->createMock(ClientInterface::class);
        $inner->method('sendRequest')->willReturn($response);

        $client = new AuthenticatedHttpClient(
            $inner,
            new ConsumerCredentials('my-consumer-key', 'cs'),
            new Token('my-access-token', 'as'),
            new HmacSha1(),
        );

        $uri = $this->createMock(UriInterface::class);
        $uri->method('__toString')->willReturn('https://api.example.com/data');

        $request = $this->createMock(RequestInterface::class);
        $request->method('getMethod')->willReturn('GET');
        $request->method('getUri')->willReturn($uri);
        $request->method('withHeader')->willReturnCallback(
            function (string $name, $value) use (&$authHeader, $request): RequestInterface {
                if (strtolower($name) === 'authorization') {
                    $authHeader = $value;
                }
                return $request;
            }
        );

        $client->sendRequest($request);

        self::assertNotNull($authHeader);
        self::assertStringStartsWith('OAuth ', $authHeader);
        self::assertStringContainsString('oauth_consumer_key="my-consumer-key"', $authHeader);
        self::assertStringContainsString('oauth_token="my-access-token"', $authHeader);
        self::assertStringContainsString('oauth_signature_method="HMAC-SHA1"', $authHeader);
        self::assertStringContainsString('oauth_version="1.0"', $authHeader);
        self::assertStringContainsString('oauth_nonce=', $authHeader);
        self::assertStringContainsString('oauth_timestamp=', $authHeader);
        self::assertStringContainsString('oauth_signature=', $authHeader);
    }

    public function testDelegatesResponseFromInner(): void
    {
        $body = $this->createMock(StreamInterface::class);
        $body->method('__toString')->willReturn('{"data": true}');

        $expectedResponse = $this->createMock(ResponseInterface::class);
        $expectedResponse->method('getStatusCode')->willReturn(200);
        $expectedResponse->method('getBody')->willReturn($body);

        $inner = $this->createMock(ClientInterface::class);
        $inner->method('sendRequest')->willReturn($expectedResponse);

        $client = new AuthenticatedHttpClient(
            $inner,
            new ConsumerCredentials('ck', 'cs'),
            new Token('at', 'as'),
            new HmacSha1(),
        );

        $uri = $this->createMock(UriInterface::class);
        $uri->method('__toString')->willReturn('https://api.example.com/data');

        $request = $this->createMock(RequestInterface::class);
        $request->method('getMethod')->willReturn('GET');
        $request->method('getUri')->willReturn($uri);
        $request->method('withHeader')->willReturnSelf();

        $response = $client->sendRequest($request);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('{"data": true}', (string) $response->getBody());
    }
}
