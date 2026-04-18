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
use Horde\Jwt\Key\PublicKey;
use Horde\Oauth\Oidc\Handler\JwksEndpoint;
use Horde\Oauth\Test\RsaKeyHelper;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(JwksEndpoint::class)]
final class JwksEndpointTest extends TestCase
{
    use RsaKeyHelper;

    public function testReturnsJwksJson(): void
    {
        $rsaKey = self::generateRsaKey();
        $pubKey = PublicKey::fromPrivateKey($rsaKey);
        $handler = new JwksEndpoint($pubKey, new ResponseFactory(), new StreamFactory(), 'my-key-id');
        $response = $handler->handle(new ServerRequest('GET', 'https://example.com/.well-known/jwks.json'));

        self::assertSame(200, $response->getStatusCode());
        self::assertStringContainsString('application/json', $response->getHeaderLine('Content-Type'));
        $body = json_decode((string) $response->getBody(), true);
        self::assertArrayHasKey('keys', $body);
        self::assertCount(1, $body['keys']);
        $key = $body['keys'][0];
        self::assertSame('my-key-id', $key['kid']);
        self::assertSame('RS256', $key['alg']);
        self::assertSame('RSA', $key['kty']);
        self::assertArrayHasKey('n', $key);
        self::assertArrayHasKey('e', $key);
    }
}
