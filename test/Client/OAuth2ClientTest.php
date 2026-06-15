<?php

declare(strict_types=1);

/**
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 *
 * @author   Jean Charles Delépine <jean.charles.delepine@u-picardie.fr>
 */

namespace Horde\OAuth\Test\Client;

use Horde\OAuth\Client\OAuth2Client;
use Horde\OAuth\Client\ProviderConfig;
use Horde\OAuth\Exception\OAuthException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;

#[CoversClass(OAuth2Client::class)]
final class OAuth2ClientTest extends TestCase
{
    private ProviderConfig $provider;
    private RequestInterface $request;
    private StreamInterface $stream;
    private StreamFactoryInterface $streamFactory;

    protected function setUp(): void
    {
        $this->provider = ProviderConfig::fromArray([
            'issuer'                                => 'https://idp.example.org',
            'authorization_endpoint'                => 'https://idp.example.org/authorize',
            'token_endpoint'                        => 'https://idp.example.org/token',
            'revocation_endpoint'                   => 'https://idp.example.org/revoke',
            'token_endpoint_auth_methods_supported' => ['client_secret_post'],
        ]);

        $this->stream        = $this->createStub(StreamInterface::class);
        $this->request       = $this->createStub(RequestInterface::class);
        $this->streamFactory = $this->createStub(StreamFactoryInterface::class);

        $this->request->method('withHeader')->willReturnSelf();
        $this->request->method('withBody')->willReturnSelf();
        $this->streamFactory->method('createStream')->willReturn($this->stream);
    }

    private function makeClient(
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        ?string $clientSecret = 'secret',
        ?ProviderConfig $provider = null,
    ): OAuth2Client {
        return new OAuth2Client(
            provider: $provider ?? $this->provider,
            clientId: 'test-client',
            clientSecret: $clientSecret,
            redirectUri: 'https://horde.example.org/callback',
            httpClient: $httpClient,
            requestFactory: $requestFactory,
            streamFactory: $this->streamFactory,
        );
    }

    /**
     * Returns a stream factory whose createStream() captures the body string
     * passed in, then returns the shared $this->stream stub. Use when a test
     * needs to assert on the wire body without touching a real HTTP layer.
     */
    private function captureStreamBody(?string &$captured): StreamFactoryInterface
    {
        $factory = $this->createStub(StreamFactoryInterface::class);
        $factory->method('createStream')
            ->willReturnCallback(function (string $body) use (&$captured): StreamInterface {
                $captured = $body;
                return $this->stream;
            });
        return $factory;
    }

    /**
     * Returns a fresh RequestInterface stub (NOT $this->request) whose
     * withHeader() captures any "Authorization" value into $captured and
     * returns itself. withBody() also returns itself so the production
     * code's fluent chain (withHeader()->withHeader()->withBody()->...)
     * resolves correctly.
     *
     * Using a fresh stub here — instead of re-stubbing $this->request from
     * setUp() — avoids PHPUnit's matcher-fallthrough behaviour when the
     * same method is configured twice on the same stub.
     */
    private function captureAuthHeader(?string &$captured): RequestInterface
    {
        $request = $this->createStub(RequestInterface::class);
        $request->method('withBody')->willReturn($request);
        $request->method('withHeader')
            ->willReturnCallback(function (string $name, string $value) use (&$captured, $request): RequestInterface {
                if ($name === 'Authorization') {
                    $captured = $value;
                }
                return $request;
            });
        return $request;
    }

    public function testRevokeTokenSendsPostToRevocationEndpoint(): void
    {
        $requestFactory = $this->createMock(RequestFactoryInterface::class);
        $requestFactory
            ->expects(self::once())
            ->method('createRequest')
            ->with('POST', 'https://idp.example.org/revoke')
            ->willReturn($this->request);

        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);

        $httpClient = $this->createMock(ClientInterface::class);
        $httpClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturn($response);

        $this->makeClient($httpClient, $requestFactory)->revokeToken('my-access-token');
    }

    public function testRevokeTokenIncludesTokenInBodyWhenPostConfigured(): void
    {
        $requestFactory = $this->createStub(RequestFactoryInterface::class);
        $requestFactory->method('createRequest')->willReturn($this->request);

        $capturedBody = null;
        $streamFactory = $this->captureStreamBody($capturedBody);

        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);

        $httpClient = $this->createStub(ClientInterface::class);
        $httpClient->method('sendRequest')->willReturn($response);

        $client = new OAuth2Client(
            provider: $this->provider,
            clientId: 'test-client',
            clientSecret: 'secret',
            redirectUri: 'https://horde.example.org/callback',
            httpClient: $httpClient,
            requestFactory: $requestFactory,
            streamFactory: $streamFactory,
        );

        $client->revokeToken('my-access-token', 'access_token');

        self::assertStringContainsString('token=my-access-token', $capturedBody);
        self::assertStringContainsString('token_type_hint=access_token', $capturedBody);
        self::assertStringContainsString('client_id=test-client', $capturedBody);
        self::assertStringContainsString('client_secret=secret', $capturedBody);
    }

    public function testRevokeTokenWithDefaultHintIsAccessToken(): void
    {
        $requestFactory = $this->createStub(RequestFactoryInterface::class);
        $requestFactory->method('createRequest')->willReturn($this->request);

        $capturedBody = null;
        $streamFactory = $this->captureStreamBody($capturedBody);

        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);

        $httpClient = $this->createStub(ClientInterface::class);
        $httpClient->method('sendRequest')->willReturn($response);

        $client = new OAuth2Client(
            provider: $this->provider,
            clientId: 'test-client',
            clientSecret: 'secret',
            redirectUri: 'https://horde.example.org/callback',
            httpClient: $httpClient,
            requestFactory: $requestFactory,
            streamFactory: $streamFactory,
        );

        $client->revokeToken('my-token');

        self::assertStringContainsString('token_type_hint=access_token', $capturedBody);
    }

    public function testRevokeTokenWithoutClientSecretOmitsIt(): void
    {
        $requestFactory = $this->createStub(RequestFactoryInterface::class);
        $requestFactory->method('createRequest')->willReturn($this->request);

        $capturedBody = null;
        $streamFactory = $this->captureStreamBody($capturedBody);

        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);

        $httpClient = $this->createStub(ClientInterface::class);
        $httpClient->method('sendRequest')->willReturn($response);

        $client = new OAuth2Client(
            provider: $this->provider,
            clientId: 'test-client',
            clientSecret: null,
            redirectUri: 'https://horde.example.org/callback',
            httpClient: $httpClient,
            requestFactory: $requestFactory,
            streamFactory: $streamFactory,
        );

        $client->revokeToken('my-token');

        self::assertStringNotContainsString('client_secret', $capturedBody);
    }

    public function testRevokeTokenThrowsWhenNoRevocationEndpoint(): void
    {
        $provider = ProviderConfig::fromArray([
            'issuer'                 => 'https://idp.example.org',
            'authorization_endpoint' => 'https://idp.example.org/authorize',
            'token_endpoint'         => 'https://idp.example.org/token',
        ]);

        $httpClient     = $this->createStub(ClientInterface::class);
        $requestFactory = $this->createStub(RequestFactoryInterface::class);

        $client = new OAuth2Client(
            provider: $provider,
            clientId: 'test-client',
            clientSecret: 'secret',
            redirectUri: 'https://horde.example.org/callback',
            httpClient: $httpClient,
            requestFactory: $requestFactory,
            streamFactory: $this->streamFactory,
        );

        $this->expectException(OAuthException::class);
        $client->revokeToken('my-token');
    }

    public function testRevokeTokenThrowsOnErrorResponse(): void
    {
        $requestFactory = $this->createStub(RequestFactoryInterface::class);
        $requestFactory->method('createRequest')->willReturn($this->request);

        $body = $this->createStub(StreamInterface::class);
        $body->method('__toString')->willReturn('{"error":"invalid_token","error_description":"Token expired"}');

        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(400);
        $response->method('getBody')->willReturn($body);

        $httpClient = $this->createStub(ClientInterface::class);
        $httpClient->method('sendRequest')->willReturn($response);

        $this->expectException(OAuthException::class);
        $this->makeClient($httpClient, $requestFactory)->revokeToken('bad-token');
    }

    public function testRevokeTokenUsesBasicAuthWhenConfigured(): void
    {
        $provider = ProviderConfig::fromArray([
            'issuer'                                => 'https://idp.example.org',
            'authorization_endpoint'                => 'https://idp.example.org/authorize',
            'token_endpoint'                        => 'https://idp.example.org/token',
            'revocation_endpoint'                   => 'https://idp.example.org/revoke',
            'token_endpoint_auth_methods_supported' => ['client_secret_basic'],
        ]);

        $capturedAuth = null;
        $request      = $this->captureAuthHeader($capturedAuth);

        $requestFactory = $this->createStub(RequestFactoryInterface::class);
        $requestFactory->method('createRequest')->willReturn($request);

        $capturedBody  = null;
        $streamFactory = $this->captureStreamBody($capturedBody);

        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);

        $httpClient = $this->createStub(ClientInterface::class);
        $httpClient->method('sendRequest')->willReturn($response);

        $client = new OAuth2Client(
            provider: $provider,
            clientId: 'test-client',
            clientSecret: 'secret',
            redirectUri: 'https://horde.example.org/callback',
            httpClient: $httpClient,
            requestFactory: $requestFactory,
            streamFactory: $streamFactory,
        );

        $client->revokeToken('my-token');

        self::assertStringNotContainsString('client_secret', $capturedBody);
        self::assertStringStartsWith('Basic ', $capturedAuth);
        self::assertSame(
            'Basic ' . base64_encode(urlencode('test-client') . ':' . urlencode('secret')),
            $capturedAuth
        );
    }

    public function testRevokeTokenUsesPostWhenBothMethodsSupported(): void
    {
        $provider = ProviderConfig::fromArray([
            'issuer'                                => 'https://idp.example.org',
            'authorization_endpoint'                => 'https://idp.example.org/authorize',
            'token_endpoint'                        => 'https://idp.example.org/token',
            'revocation_endpoint'                   => 'https://idp.example.org/revoke',
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post'],
        ]);

        $requestFactory = $this->createStub(RequestFactoryInterface::class);
        $requestFactory->method('createRequest')->willReturn($this->request);

        $capturedBody  = null;
        $streamFactory = $this->captureStreamBody($capturedBody);

        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);

        $httpClient = $this->createStub(ClientInterface::class);
        $httpClient->method('sendRequest')->willReturn($response);

        $client = new OAuth2Client(
            provider: $provider,
            clientId: 'test-client',
            clientSecret: 'secret',
            redirectUri: 'https://horde.example.org/callback',
            httpClient: $httpClient,
            requestFactory: $requestFactory,
            streamFactory: $streamFactory,
        );

        $client->revokeToken('my-token');

        self::assertStringContainsString('client_secret=secret', $capturedBody);
    }

    public function testRevokeTokenPrefersRevocationAuthMethodsWhenAdvertised(): void
    {
        // Token endpoint advertises post; revocation endpoint advertises
        // basic only. The override must win for revokeToken().
        $provider = ProviderConfig::fromArray([
            'issuer'                                     => 'https://idp.example.org',
            'authorization_endpoint'                     => 'https://idp.example.org/authorize',
            'token_endpoint'                             => 'https://idp.example.org/token',
            'revocation_endpoint'                        => 'https://idp.example.org/revoke',
            'token_endpoint_auth_methods_supported'      => ['client_secret_post'],
            'revocation_endpoint_auth_methods_supported' => ['client_secret_basic'],
        ]);

        $capturedAuth = null;
        $request      = $this->captureAuthHeader($capturedAuth);

        $requestFactory = $this->createStub(RequestFactoryInterface::class);
        $requestFactory->method('createRequest')->willReturn($request);

        $capturedBody  = null;
        $streamFactory = $this->captureStreamBody($capturedBody);

        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);

        $httpClient = $this->createStub(ClientInterface::class);
        $httpClient->method('sendRequest')->willReturn($response);

        $client = new OAuth2Client(
            provider: $provider,
            clientId: 'test-client',
            clientSecret: 'secret',
            redirectUri: 'https://horde.example.org/callback',
            httpClient: $httpClient,
            requestFactory: $requestFactory,
            streamFactory: $streamFactory,
        );

        $client->revokeToken('my-token');

        self::assertStringNotContainsString('client_secret', $capturedBody);
        self::assertStringStartsWith('Basic ', $capturedAuth);
    }

    public function testRevokeTokenFallsBackToTokenAuthMethodsWhenRevocationNotAdvertised(): void
    {
        // Revocation endpoint advertises no auth methods. Per RFC 8414 §2,
        // fall back to the token endpoint's advertised methods.
        $provider = ProviderConfig::fromArray([
            'issuer'                                => 'https://idp.example.org',
            'authorization_endpoint'                => 'https://idp.example.org/authorize',
            'token_endpoint'                        => 'https://idp.example.org/token',
            'revocation_endpoint'                   => 'https://idp.example.org/revoke',
            'token_endpoint_auth_methods_supported' => ['client_secret_basic'],
        ]);

        $capturedAuth = null;
        $request      = $this->captureAuthHeader($capturedAuth);

        $requestFactory = $this->createStub(RequestFactoryInterface::class);
        $requestFactory->method('createRequest')->willReturn($request);

        $capturedBody  = null;
        $streamFactory = $this->captureStreamBody($capturedBody);

        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);

        $httpClient = $this->createStub(ClientInterface::class);
        $httpClient->method('sendRequest')->willReturn($response);

        $client = new OAuth2Client(
            provider: $provider,
            clientId: 'test-client',
            clientSecret: 'secret',
            redirectUri: 'https://horde.example.org/callback',
            httpClient: $httpClient,
            requestFactory: $requestFactory,
            streamFactory: $streamFactory,
        );

        $client->revokeToken('my-token');

        self::assertStringNotContainsString('client_secret', $capturedBody);
        self::assertStringStartsWith('Basic ', $capturedAuth);
    }
}
