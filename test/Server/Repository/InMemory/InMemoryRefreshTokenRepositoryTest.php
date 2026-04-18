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

namespace Horde\Oauth\Test\Server\Repository\InMemory;

use Horde\Oauth\Server\Entity\RefreshToken;
use Horde\Oauth\Server\Repository\InMemory\InMemoryRefreshTokenRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use DateTimeImmutable;

#[CoversClass(InMemoryRefreshTokenRepository::class)]
final class InMemoryRefreshTokenRepositoryTest extends TestCase
{
    public function testPersistAndFind(): void
    {
        $repo = new InMemoryRefreshTokenRepository();
        $token = new RefreshToken('rt1', 'at1', 'c1', 'u1', 'openid', new DateTimeImmutable('+30 days'));
        $repo->persist($token);
        self::assertSame($token, $repo->findById('rt1'));
    }

    public function testRevokeAndIsRevoked(): void
    {
        $repo = new InMemoryRefreshTokenRepository();
        $token = new RefreshToken('rt1', 'at1', 'c1', 'u1', 'openid', new DateTimeImmutable('+30 days'));
        $repo->persist($token);

        self::assertFalse($repo->isRevoked('rt1'));
        $repo->revoke('rt1');
        self::assertTrue($repo->isRevoked('rt1'));
    }

    public function testRevokeByAccessTokenId(): void
    {
        $repo = new InMemoryRefreshTokenRepository();
        $repo->persist(new RefreshToken('rt1', 'at1', 'c1', 'u1', 'openid', new DateTimeImmutable('+30 days')));
        $repo->persist(new RefreshToken('rt2', 'at1', 'c1', 'u1', 'openid', new DateTimeImmutable('+30 days')));
        $repo->persist(new RefreshToken('rt3', 'at2', 'c1', 'u1', 'openid', new DateTimeImmutable('+30 days')));

        $repo->revokeByAccessTokenId('at1');
        self::assertTrue($repo->isRevoked('rt1'));
        self::assertTrue($repo->isRevoked('rt2'));
        self::assertFalse($repo->isRevoked('rt3'));
    }
}
