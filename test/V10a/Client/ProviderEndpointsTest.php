<?php

declare(strict_types=1);

/**
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\Test\V10a\Client;

use Horde\OAuth\V10a\Client\ProviderEndpoints;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ProviderEndpoints::class)]
final class ProviderEndpointsTest extends TestCase
{
    public function testProperties(): void
    {
        $ep = new ProviderEndpoints(
            'https://provider.example/request_token',
            'https://provider.example/authorize',
            'https://provider.example/access_token',
        );
        self::assertSame('https://provider.example/request_token', $ep->requestTokenUrl);
        self::assertSame('https://provider.example/authorize', $ep->authorizeUrl);
        self::assertSame('https://provider.example/access_token', $ep->accessTokenUrl);
    }
}
