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

namespace Horde\Oauth\Test\Server\Handler;

use Horde\Http\ResponseFactory;
use Horde\Http\ServerRequest;
use Horde\Http\StreamFactory;
use Horde\Oauth\Server\Entity\Client;
use Horde\Oauth\Server\Entity\Scope;
use Horde\Oauth\Server\Handler\AuthorizationEndpoint;
use Horde\Oauth\Server\AuthorizationResult;
use Horde\Oauth\Server\Repository\InMemory\InMemoryAuthorizationCodeRepository;
use Horde\Oauth\Server\Repository\InMemory\InMemoryClientRepository;
use Horde\Oauth\Server\Repository\InMemory\InMemoryScopeRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(AuthorizationEndpoint::class)]
final class AuthorizationEndpointTest extends TestCase
{
    private AuthorizationEndpoint $handler;
    private InMemoryAuthorizationCodeRepository $codeRepo;

    protected function setUp(): void
    {
        $client = new Client(
            'c1',
            null,
            'Test App',
            ['https://example.com/cb'],
            ['authorization_code'],
            'openid profile',
            'public',
        );
        $clientRepo = new InMemoryClientRepository($client);
        $scopeRepo = new InMemoryScopeRepository(new Scope('openid'), new Scope('profile'));
        $this->codeRepo = new InMemoryAuthorizationCodeRepository();
        $this->handler = new AuthorizationEndpoint(
            $clientRepo,
            $scopeRepo,
            $this->codeRepo,
            new ResponseFactory(),
            new StreamFactory(),
        );
    }

    public function testValidateAuthorizationRequest(): void
    {
        $request = (new ServerRequest('GET', 'https://example.com/authorize'))
            ->withQueryParams([
                'response_type' => 'code',
                'client_id' => 'c1',
                'redirect_uri' => 'https://example.com/cb',
                'scope' => 'openid',
                'state' => 'xyz',
                'nonce' => 'n1',
            ]);
        $authRequest = $this->handler->validateAuthorizationRequest($request);
        self::assertSame('c1', $authRequest->client->clientId);
        self::assertSame('xyz', $authRequest->state);
        self::assertSame('n1', $authRequest->nonce);
    }

    public function testValidateDefaultsRedirectUri(): void
    {
        $request = (new ServerRequest('GET', 'https://example.com/authorize'))
            ->withQueryParams([
                'response_type' => 'code',
                'client_id' => 'c1',
                'scope' => 'openid',
            ]);
        $authRequest = $this->handler->validateAuthorizationRequest($request);
        self::assertSame('https://example.com/cb', $authRequest->redirectUri);
    }

    public function testCompleteApproved(): void
    {
        $request = (new ServerRequest('GET', 'https://example.com/authorize'))
            ->withQueryParams([
                'response_type' => 'code',
                'client_id' => 'c1',
                'redirect_uri' => 'https://example.com/cb',
                'scope' => 'openid',
                'state' => 'xyz',
            ]);
        $authRequest = $this->handler->validateAuthorizationRequest($request);
        $result = new AuthorizationResult($authRequest, true, 'user1');
        $response = $this->handler->completeAuthorizationRequest($result);

        self::assertSame(302, $response->getStatusCode());
        $location = $response->getHeaderLine('Location');
        self::assertStringContainsString('code=', $location);
        self::assertStringContainsString('state=xyz', $location);
    }

    public function testCompleteDenied(): void
    {
        $request = (new ServerRequest('GET', 'https://example.com/authorize'))
            ->withQueryParams([
                'response_type' => 'code',
                'client_id' => 'c1',
                'redirect_uri' => 'https://example.com/cb',
                'state' => 'xyz',
            ]);
        $authRequest = $this->handler->validateAuthorizationRequest($request);
        $result = new AuthorizationResult($authRequest, false, null);
        $response = $this->handler->completeAuthorizationRequest($result);

        self::assertSame(302, $response->getStatusCode());
        $location = $response->getHeaderLine('Location');
        self::assertStringContainsString('error=access_denied', $location);
        self::assertStringContainsString('state=xyz', $location);
    }

    public function testHandleReturnsJson(): void
    {
        $request = (new ServerRequest('GET', 'https://example.com/authorize'))
            ->withQueryParams([
                'response_type' => 'code',
                'client_id' => 'c1',
                'redirect_uri' => 'https://example.com/cb',
                'scope' => 'openid',
            ]);
        $response = $this->handler->handle($request);
        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertSame('c1', $body['client_id']);
    }

    public function testHandleInvalidRequest(): void
    {
        $request = (new ServerRequest('GET', 'https://example.com/authorize'))
            ->withQueryParams(['response_type' => 'token']);
        $response = $this->handler->handle($request);
        self::assertSame(400, $response->getStatusCode());
    }
}
