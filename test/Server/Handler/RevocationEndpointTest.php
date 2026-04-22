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

namespace Horde\OAuth\Test\Server\Handler;

use Horde\Http\ResponseFactory;
use Horde\Http\ServerRequest;
use Horde\Http\StreamFactory;
use Horde\OAuth\Server\ClientAuthentication\ClientAuthenticatorChain;
use Horde\OAuth\Server\ClientAuthentication\ClientSecretBasic;
use Horde\OAuth\Server\Entity\AccessToken;
use Horde\OAuth\Server\Entity\Client;
use Horde\OAuth\Server\Handler\RevocationEndpoint;
use Horde\OAuth\Server\Repository\InMemory\InMemoryAccessTokenRepository;
use Horde\OAuth\Server\Repository\InMemory\InMemoryClientRepository;
use Horde\OAuth\Server\Repository\InMemory\InMemoryRefreshTokenRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use DateTimeImmutable;

#[CoversClass(RevocationEndpoint::class)]
final class RevocationEndpointTest extends TestCase
{
    private RevocationEndpoint $handler;
    private InMemoryAccessTokenRepository $atRepo;

    protected function setUp(): void
    {
        $client = new Client('c1', password_hash('s', PASSWORD_BCRYPT), 'Test', [], ['client_credentials'], 'api', 'confidential');
        $clientRepo = new InMemoryClientRepository($client);
        $chain = new ClientAuthenticatorChain($clientRepo, new ClientSecretBasic());
        $this->atRepo = new InMemoryAccessTokenRepository();
        $rtRepo = new InMemoryRefreshTokenRepository();
        $this->handler = new RevocationEndpoint($chain, $this->atRepo, $rtRepo, new ResponseFactory(), new StreamFactory());
    }

    private function authHeader(): string
    {
        return 'Basic ' . base64_encode('c1:s');
    }

    public function testRevokesAccessToken(): void
    {
        $this->atRepo->persist(new AccessToken('jti1', 'c1', 'user1', 'api', new DateTimeImmutable('+1 hour')));
        $request = (new ServerRequest('POST', 'https://example.com/revoke'))
            ->withHeader('Authorization', $this->authHeader())
            ->withParsedBody(['token' => 'jti1', 'token_type_hint' => 'access_token']);
        $response = $this->handler->handle($request);
        self::assertSame(200, $response->getStatusCode());
        self::assertTrue($this->atRepo->isRevoked('jti1'));
    }

    public function testRevokeMissingTokenReturns200(): void
    {
        $request = (new ServerRequest('POST', 'https://example.com/revoke'))
            ->withHeader('Authorization', $this->authHeader())
            ->withParsedBody([]);
        $response = $this->handler->handle($request);
        self::assertSame(200, $response->getStatusCode());
    }

    public function testUnauthenticatedReturnsError(): void
    {
        $request = (new ServerRequest('POST', 'https://example.com/revoke'))
            ->withParsedBody(['token' => 'jti1']);
        $response = $this->handler->handle($request);
        self::assertSame(401, $response->getStatusCode());
    }
}
