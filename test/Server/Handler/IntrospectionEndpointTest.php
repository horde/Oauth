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
use Horde\Oauth\Server\ClientAuthentication\ClientAuthenticatorChain;
use Horde\Oauth\Server\ClientAuthentication\ClientSecretBasic;
use Horde\Oauth\Server\Entity\AccessToken;
use Horde\Oauth\Server\Entity\Client;
use Horde\Oauth\Server\Handler\IntrospectionEndpoint;
use Horde\Oauth\Server\Repository\InMemory\InMemoryAccessTokenRepository;
use Horde\Oauth\Server\Repository\InMemory\InMemoryClientRepository;
use Horde\Oauth\Server\Repository\InMemory\InMemoryRefreshTokenRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use DateTimeImmutable;

#[CoversClass(IntrospectionEndpoint::class)]
final class IntrospectionEndpointTest extends TestCase
{
    private IntrospectionEndpoint $handler;
    private InMemoryAccessTokenRepository $atRepo;

    protected function setUp(): void
    {
        $client = new Client(
            'c1',
            password_hash('s', PASSWORD_BCRYPT),
            'Test',
            [],
            ['client_credentials'],
            'api',
            'confidential',
        );
        $clientRepo = new InMemoryClientRepository($client);
        $chain = new ClientAuthenticatorChain($clientRepo, new ClientSecretBasic());
        $this->atRepo = new InMemoryAccessTokenRepository();
        $rtRepo = new InMemoryRefreshTokenRepository();
        $this->handler = new IntrospectionEndpoint($chain, $this->atRepo, $rtRepo, new ResponseFactory(), new StreamFactory());
    }

    private function authHeader(): string
    {
        return 'Basic ' . base64_encode('c1:s');
    }

    public function testActiveToken(): void
    {
        $this->atRepo->persist(new AccessToken('jti1', 'c1', 'user1', 'api', new DateTimeImmutable('+1 hour')));
        $request = (new ServerRequest('POST', 'https://example.com/introspect'))
            ->withHeader('Authorization', $this->authHeader())
            ->withParsedBody(['token' => 'jti1']);
        $response = $this->handler->handle($request);
        $body = json_decode((string) $response->getBody(), true);
        self::assertTrue($body['active']);
        self::assertSame('api', $body['scope']);
        self::assertSame('Bearer', $body['token_type']);
    }

    public function testInactiveToken(): void
    {
        $request = (new ServerRequest('POST', 'https://example.com/introspect'))
            ->withHeader('Authorization', $this->authHeader())
            ->withParsedBody(['token' => 'nonexistent']);
        $response = $this->handler->handle($request);
        $body = json_decode((string) $response->getBody(), true);
        self::assertFalse($body['active']);
    }

    public function testRevokedTokenInactive(): void
    {
        $this->atRepo->persist(new AccessToken('jti1', 'c1', 'user1', 'api', new DateTimeImmutable('+1 hour'), revoked: true));
        $request = (new ServerRequest('POST', 'https://example.com/introspect'))
            ->withHeader('Authorization', $this->authHeader())
            ->withParsedBody(['token' => 'jti1']);
        $response = $this->handler->handle($request);
        $body = json_decode((string) $response->getBody(), true);
        self::assertFalse($body['active']);
    }

    public function testMissingTokenReturnsInactive(): void
    {
        $request = (new ServerRequest('POST', 'https://example.com/introspect'))
            ->withHeader('Authorization', $this->authHeader())
            ->withParsedBody([]);
        $response = $this->handler->handle($request);
        $body = json_decode((string) $response->getBody(), true);
        self::assertFalse($body['active']);
    }

    public function testUnauthenticatedReturnsError(): void
    {
        $request = (new ServerRequest('POST', 'https://example.com/introspect'))
            ->withParsedBody(['token' => 'jti1']);
        $response = $this->handler->handle($request);
        self::assertSame(401, $response->getStatusCode());
    }
}
