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
use Horde\Oauth\Oidc\Handler\DiscoveryEndpoint;
use Horde\Oauth\Server\ServerMetadata;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(DiscoveryEndpoint::class)]
final class DiscoveryEndpointTest extends TestCase
{
    public function testReturnsDiscoveryDocument(): void
    {
        $meta = new ServerMetadata(
            'https://example.com',
            '/authorize',
            '/token',
            jwksUri: 'https://example.com/.well-known/jwks.json',
            userinfoEndpoint: 'https://example.com/userinfo',
        );
        $handler = new DiscoveryEndpoint($meta, new ResponseFactory(), new StreamFactory());
        $response = $handler->handle(new ServerRequest('GET', 'https://example.com/.well-known/openid-configuration'));

        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertSame('https://example.com', $body['issuer']);
        self::assertSame('https://example.com/.well-known/jwks.json', $body['jwks_uri']);
    }
}
