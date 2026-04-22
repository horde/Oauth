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

namespace Horde\OAuth\Test\Server\Entity;

use Horde\OAuth\Server\Entity\RefreshToken;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use DateTimeImmutable;

#[CoversClass(RefreshToken::class)]
final class RefreshTokenTest extends TestCase
{
    public function testNotExpiredNotRevoked(): void
    {
        $token = new RefreshToken('rt1', 'at1', 'client1', 'user1', 'openid', new DateTimeImmutable('+30 days'));
        self::assertFalse($token->isExpired());
        self::assertFalse($token->isRevoked());
    }

    public function testExpired(): void
    {
        $token = new RefreshToken('rt1', 'at1', 'client1', 'user1', 'openid', new DateTimeImmutable('-1 second'));
        self::assertTrue($token->isExpired());
    }

    public function testRevoked(): void
    {
        $token = new RefreshToken('rt1', 'at1', 'client1', 'user1', 'openid', new DateTimeImmutable('+30 days'), revoked: true);
        self::assertTrue($token->isRevoked());
    }
}
