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

namespace Horde\Oauth\Test\Client;

use Horde\Oauth\Client\ProviderConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ProviderConfig::class)]
final class ProviderConfigTest extends TestCase
{
    public function testFromArray(): void
    {
        $cfg = ProviderConfig::fromArray([
            'issuer' => 'https://example.com',
            'authorization_endpoint' => 'https://example.com/authorize',
            'token_endpoint' => 'https://example.com/token',
            'userinfo_endpoint' => 'https://example.com/userinfo',
            'jwks_uri' => 'https://example.com/.well-known/jwks.json',
            'scopes_supported' => ['openid', 'profile'],
        ]);
        self::assertSame('https://example.com', $cfg->issuer);
        self::assertSame('https://example.com/authorize', $cfg->authorizationEndpoint);
        self::assertSame('https://example.com/token', $cfg->tokenEndpoint);
        self::assertSame('https://example.com/userinfo', $cfg->userinfoEndpoint);
        self::assertSame('https://example.com/.well-known/jwks.json', $cfg->jwksUri);
        self::assertSame(['openid', 'profile'], $cfg->scopesSupported);
    }

    public function testFromArrayDefaults(): void
    {
        $cfg = ProviderConfig::fromArray([]);
        self::assertSame('', $cfg->issuer);
        self::assertNull($cfg->userinfoEndpoint);
        self::assertSame(['code'], $cfg->responseTypesSupported);
    }

    public function testToArray(): void
    {
        $cfg = new ProviderConfig(
            'https://example.com',
            '/auth',
            '/token',
            userinfoEndpoint: '/userinfo',
            scopesSupported: ['openid'],
        );
        $arr = $cfg->toArray();
        self::assertSame('https://example.com', $arr['issuer']);
        self::assertSame('/userinfo', $arr['userinfo_endpoint']);
        self::assertArrayNotHasKey('jwks_uri', $arr);
    }
}
