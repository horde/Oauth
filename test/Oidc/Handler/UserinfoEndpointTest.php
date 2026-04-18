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

namespace Horde\Oauth\Test\Oidc\Handler;

use Horde\Http\ResponseFactory;
use Horde\Http\ServerRequest;
use Horde\Http\StreamFactory;
use Horde\Oauth\Oidc\ClaimsMapper;
use Horde\Oauth\Oidc\Handler\UserinfoEndpoint;
use Horde\Oauth\Oidc\ScopeClaimsMapping;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(UserinfoEndpoint::class)]
final class UserinfoEndpointTest extends TestCase
{
    private UserinfoEndpoint $handler;

    protected function setUp(): void
    {
        $claimsMapper = new class implements ClaimsMapper {
            public function getClaims(string $identityId, array $claimNames): array
            {
                return array_intersect_key(
                    ['name' => 'Test User', 'email' => 'test@example.com'],
                    array_flip($claimNames),
                );
            }
        };
        $this->handler = new UserinfoEndpoint(
            $claimsMapper,
            new ScopeClaimsMapping(),
            new ResponseFactory(),
            new StreamFactory(),
        );
    }

    public function testReturnsClaimsForAuthenticatedUser(): void
    {
        $request = (new ServerRequest('GET', 'https://example.com/userinfo'))
            ->withAttribute('oauth_user_id', 'user1')
            ->withAttribute('oauth_scopes', 'openid profile email');
        $response = $this->handler->handle($request);
        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertSame('user1', $body['sub']);
        self::assertSame('Test User', $body['name']);
        self::assertSame('test@example.com', $body['email']);
    }

    public function testReturns401WithoutUser(): void
    {
        $request = new ServerRequest('GET', 'https://example.com/userinfo');
        $response = $this->handler->handle($request);
        self::assertSame(401, $response->getStatusCode());
        self::assertStringContainsString('Bearer', $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testRespectsScopes(): void
    {
        $request = (new ServerRequest('GET', 'https://example.com/userinfo'))
            ->withAttribute('oauth_user_id', 'user1')
            ->withAttribute('oauth_scopes', 'openid profile');
        $response = $this->handler->handle($request);
        $body = json_decode((string) $response->getBody(), true);
        self::assertSame('Test User', $body['name']);
        self::assertArrayNotHasKey('email', $body);
    }
}
