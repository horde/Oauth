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

use Horde\OAuth\Server\Entity\Client;
use Horde\OAuth\Server\Entity\Scope;
use Horde\OAuth\Server\Repository\InMemory\InMemoryRefreshTokenRepository;
use Horde\OAuth\Server\Token\RefreshTokenIssuer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(RefreshTokenIssuer::class)]
final class RefreshTokenIssuerTest extends TestCase
{
    public function testIssueReturnsOpaqueToken(): void
    {
        $repo = new InMemoryRefreshTokenRepository();
        $issuer = new RefreshTokenIssuer($repo);
        $client = new Client('c1', null, 'Test', [], ['authorization_code'], 'openid', 'public');
        $tokenId = $issuer->issue('at1', $client, 'user1', [new Scope('openid')]);

        self::assertSame(64, strlen($tokenId));
        self::assertMatchesRegularExpression('/^[0-9a-f]+$/', $tokenId);
    }

    public function testIssuePersists(): void
    {
        $repo = new InMemoryRefreshTokenRepository();
        $issuer = new RefreshTokenIssuer($repo);
        $client = new Client('c1', null, 'Test', [], ['authorization_code'], 'openid', 'public');
        $tokenId = $issuer->issue('at1', $client, 'user1', [new Scope('openid')]);

        $entity = $repo->findById($tokenId);
        self::assertNotNull($entity);
        self::assertSame('at1', $entity->accessTokenId);
        self::assertSame('c1', $entity->clientId);
        self::assertSame('user1', $entity->identityId);
    }
}
