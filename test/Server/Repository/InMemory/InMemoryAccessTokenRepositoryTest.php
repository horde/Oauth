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

use Horde\Oauth\Server\Entity\AccessToken;
use Horde\Oauth\Server\Repository\InMemory\InMemoryAccessTokenRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use DateTimeImmutable;

#[CoversClass(InMemoryAccessTokenRepository::class)]
final class InMemoryAccessTokenRepositoryTest extends TestCase
{
    public function testPersistAndFind(): void
    {
        $repo = new InMemoryAccessTokenRepository();
        $token = new AccessToken('jti1', 'c1', 'u1', 'openid', new DateTimeImmutable('+1 hour'));
        $repo->persist($token);
        self::assertSame($token, $repo->findById('jti1'));
        self::assertNull($repo->findById('missing'));
    }

    public function testRevokeAndIsRevoked(): void
    {
        $repo = new InMemoryAccessTokenRepository();
        $token = new AccessToken('jti1', 'c1', 'u1', 'openid', new DateTimeImmutable('+1 hour'));
        $repo->persist($token);

        self::assertFalse($repo->isRevoked('jti1'));
        $repo->revoke('jti1');
        self::assertTrue($repo->isRevoked('jti1'));

        $found = $repo->findById('jti1');
        self::assertTrue($found->revoked);
    }

    public function testRevokeNonExistent(): void
    {
        $repo = new InMemoryAccessTokenRepository();
        $repo->revoke('missing');
        self::assertFalse($repo->isRevoked('missing'));
    }
}
