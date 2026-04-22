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
use Horde\OAuth\Server\Handler\MetadataEndpoint;
use Horde\OAuth\Server\ServerMetadata;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(MetadataEndpoint::class)]
final class MetadataEndpointTest extends TestCase
{
    public function testReturnsMetadataAsJson(): void
    {
        $meta = new ServerMetadata('https://example.com', '/authorize', '/token');
        $handler = new MetadataEndpoint($meta, new ResponseFactory(), new StreamFactory());
        $response = $handler->handle(new ServerRequest('GET', 'https://example.com/.well-known/oauth-authorization-server'));

        self::assertSame(200, $response->getStatusCode());
        self::assertStringContainsString('application/json', $response->getHeaderLine('Content-Type'));
        $body = json_decode((string) $response->getBody(), true);
        self::assertSame('https://example.com', $body['issuer']);
    }
}
