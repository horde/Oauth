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

namespace Horde\OAuth\Test\Server\Token;

use Horde\Jwt\Key\PrivateKey;
use Horde\Jwt\Signer\Rs256Signer;
use Horde\Jwt\TokenEncoder;
use Horde\OAuth\Server\Entity\Client;
use Horde\OAuth\Server\Entity\Scope;
use Horde\OAuth\Server\Repository\InMemory\InMemoryAccessTokenRepository;
use Horde\OAuth\Server\Token\AccessTokenIssuer;
use Horde\OAuth\Test\RsaKeyHelper;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(AccessTokenIssuer::class)]
final class AccessTokenIssuerTest extends TestCase
{
    use RsaKeyHelper;
    private InMemoryAccessTokenRepository $tokenRepo;
    private AccessTokenIssuer $issuer;

    protected function setUp(): void
    {
        $rsaKey = self::generateRsaKey();
        $this->tokenRepo = new InMemoryAccessTokenRepository();
        $this->issuer = new AccessTokenIssuer(
            new TokenEncoder(),
            new Rs256Signer($rsaKey),
            $this->tokenRepo,
            'https://example.com',
            3600,
        );
    }

    public function testIssueReturnsRequiredFields(): void
    {
        $client = new Client('c1', null, 'Test', [], ['client_credentials'], 'api', 'public');
        $scopes = [new Scope('openid'), new Scope('profile')];
        $result = $this->issuer->issue($client, 'user1', $scopes);

        self::assertArrayHasKey('access_token', $result);
        self::assertSame('Bearer', $result['token_type']);
        self::assertSame(3600, $result['expires_in']);
        self::assertSame('openid profile', $result['scope']);
        self::assertArrayHasKey('_jti', $result);
    }

    public function testIssuePersistsToken(): void
    {
        $client = new Client('c1', null, 'Test', [], ['client_credentials'], 'api', 'public');
        $result = $this->issuer->issue($client, 'user1', [new Scope('openid')]);
        $jti = $result['_jti'];
        $entity = $this->tokenRepo->findById($jti);
        self::assertNotNull($entity);
        self::assertSame('c1', $entity->clientId);
        self::assertSame('user1', $entity->identityId);
    }

    public function testIssueWithNullIdentity(): void
    {
        $client = new Client('c1', null, 'Test', [], ['client_credentials'], 'api', 'public');
        $result = $this->issuer->issue($client, null, []);
        self::assertArrayNotHasKey('scope', $result);
        $entity = $this->tokenRepo->findById($result['_jti']);
        self::assertNull($entity->identityId);
    }

    public function testAccessTokenIsValidJwt(): void
    {
        $client = new Client('c1', null, 'Test', [], ['client_credentials'], 'api', 'public');
        $result = $this->issuer->issue($client, 'user1', [new Scope('api')]);
        $parts = explode('.', $result['access_token']);
        self::assertCount(3, $parts);
    }
}
