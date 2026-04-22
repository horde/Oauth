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

namespace Horde\OAuth\Test\Server;

use Horde\OAuth\Server\ServerMetadata;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ServerMetadata::class)]
final class ServerMetadataTest extends TestCase
{
    private function createMetadata(): ServerMetadata
    {
        return new ServerMetadata(
            issuer: 'https://example.com',
            authorizationEndpoint: 'https://example.com/authorize',
            tokenEndpoint: 'https://example.com/token',
            revocationEndpoint: 'https://example.com/revoke',
            jwksUri: 'https://example.com/.well-known/jwks.json',
            userinfoEndpoint: 'https://example.com/userinfo',
            scopesSupported: ['openid', 'profile', 'email'],
        );
    }

    public function testToArrayIncludesRequired(): void
    {
        $meta = $this->createMetadata();
        $arr = $meta->toArray();
        self::assertSame('https://example.com', $arr['issuer']);
        self::assertSame('https://example.com/authorize', $arr['authorization_endpoint']);
        self::assertSame('https://example.com/token', $arr['token_endpoint']);
        self::assertSame('https://example.com/revoke', $arr['revocation_endpoint']);
        self::assertSame('https://example.com/.well-known/jwks.json', $arr['jwks_uri']);
        self::assertSame(['openid', 'profile', 'email'], $arr['scopes_supported']);
    }

    public function testToArrayOmitsNulls(): void
    {
        $meta = new ServerMetadata(
            issuer: 'https://example.com',
            authorizationEndpoint: 'https://example.com/authorize',
            tokenEndpoint: 'https://example.com/token',
        );
        $arr = $meta->toArray();
        self::assertArrayNotHasKey('revocation_endpoint', $arr);
        self::assertArrayNotHasKey('introspection_endpoint', $arr);
        self::assertArrayNotHasKey('jwks_uri', $arr);
        self::assertArrayNotHasKey('userinfo_endpoint', $arr);
    }

    public function testToJsonValid(): void
    {
        $meta = $this->createMetadata();
        $json = $meta->toJson();
        $decoded = json_decode($json, true);
        self::assertSame('https://example.com', $decoded['issuer']);
    }

    public function testDefaults(): void
    {
        $meta = new ServerMetadata('https://ex.com', '/auth', '/token');
        self::assertSame(['code'], $meta->responseTypesSupported);
        self::assertContains('authorization_code', $meta->grantTypesSupported);
        self::assertContains('S256', $meta->codeChallengeMethodsSupported);
    }
}
