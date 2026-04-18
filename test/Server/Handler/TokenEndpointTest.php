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
use Horde\Jwt\Signer\Rs256Signer;
use Horde\Jwt\TokenEncoder;
use Horde\Oauth\Server\ClientAuthentication\ClientAuthenticatorChain;
use Horde\Oauth\Server\ClientAuthentication\ClientSecretBasic;
use Horde\Oauth\Server\ClientAuthentication\ClientSecretPost;
use Horde\Oauth\Server\Entity\Client;
use Horde\Oauth\Server\Entity\Scope;
use Horde\Oauth\Server\Grant\ClientCredentialsGrant;
use Horde\Oauth\Server\Handler\TokenEndpoint;
use Horde\Oauth\Server\Repository\InMemory\InMemoryAccessTokenRepository;
use Horde\Oauth\Server\Repository\InMemory\InMemoryClientRepository;
use Horde\Oauth\Server\Repository\InMemory\InMemoryScopeRepository;
use Horde\Oauth\Server\Token\AccessTokenIssuer;
use Horde\Oauth\Test\RsaKeyHelper;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(TokenEndpoint::class)]
final class TokenEndpointTest extends TestCase
{
    use RsaKeyHelper;

    private TokenEndpoint $handler;

    protected function setUp(): void
    {
        $rsaKey = self::generateRsaKey();
        $client = new Client(
            'c1',
            password_hash('secret', PASSWORD_BCRYPT),
            'Test',
            [],
            ['client_credentials'],
            'api',
            'confidential',
        );
        $clientRepo = new InMemoryClientRepository($client);
        $chain = new ClientAuthenticatorChain($clientRepo, new ClientSecretBasic(), new ClientSecretPost());
        $tokenIssuer = new AccessTokenIssuer(
            new TokenEncoder(),
            new Rs256Signer($rsaKey),
            new InMemoryAccessTokenRepository(),
            'https://example.com',
        );
        $scopeRepo = new InMemoryScopeRepository(new Scope('api'));
        $grant = new ClientCredentialsGrant($tokenIssuer, $scopeRepo);
        $this->handler = new TokenEndpoint($chain, new ResponseFactory(), new StreamFactory(), $grant);
    }

    public function testSuccessfulTokenRequest(): void
    {
        $encoded = base64_encode('c1:secret');
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withHeader('Authorization', "Basic {$encoded}")
            ->withParsedBody(['grant_type' => 'client_credentials', 'scope' => 'api']);
        $response = $this->handler->handle($request);

        self::assertSame(200, $response->getStatusCode());
        self::assertStringContainsString('application/json', $response->getHeaderLine('Content-Type'));
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));

        $body = json_decode((string) $response->getBody(), true);
        self::assertArrayHasKey('access_token', $body);
        self::assertSame('Bearer', $body['token_type']);
        self::assertArrayNotHasKey('_jti', $body);
    }

    public function testMissingGrantType(): void
    {
        $encoded = base64_encode('c1:secret');
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withHeader('Authorization', "Basic {$encoded}")
            ->withParsedBody([]);
        $response = $this->handler->handle($request);
        self::assertSame(400, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertSame('invalid_request', $body['error']);
    }

    public function testUnsupportedGrantType(): void
    {
        $encoded = base64_encode('c1:secret');
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withHeader('Authorization', "Basic {$encoded}")
            ->withParsedBody(['grant_type' => 'password']);
        $response = $this->handler->handle($request);
        self::assertSame(400, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertSame('unsupported_grant_type', $body['error']);
    }

    public function testInvalidClientCredentials(): void
    {
        $encoded = base64_encode('c1:wrong');
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withHeader('Authorization', "Basic {$encoded}")
            ->withParsedBody(['grant_type' => 'client_credentials']);
        $response = $this->handler->handle($request);
        self::assertSame(401, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertSame('invalid_client', $body['error']);
    }
}
