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

use Horde\OAuth\Server\Entity\AccessToken;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use DateTimeImmutable;

#[CoversClass(AccessToken::class)]
final class AccessTokenTest extends TestCase
{
    public function testNotExpired(): void
    {
        $token = new AccessToken('jti1', 'client1', 'user1', 'openid', new DateTimeImmutable('+1 hour'));
        self::assertFalse($token->isExpired());
        self::assertFalse($token->isRevoked());
    }

    public function testExpired(): void
    {
        $token = new AccessToken('jti1', 'client1', 'user1', 'openid', new DateTimeImmutable('-1 second'));
        self::assertTrue($token->isExpired());
    }

    public function testRevoked(): void
    {
        $token = new AccessToken('jti1', 'client1', 'user1', 'openid', new DateTimeImmutable('+1 hour'), revoked: true);
        self::assertTrue($token->isRevoked());
    }

    public function testGetScopes(): void
    {
        $token = new AccessToken('jti1', 'client1', 'user1', 'openid profile', new DateTimeImmutable('+1 hour'));
        $scopes = $token->getScopes();
        self::assertCount(2, $scopes);
        self::assertSame('openid', $scopes[0]->identifier);
        self::assertSame('profile', $scopes[1]->identifier);
    }

    public function testNullIdentity(): void
    {
        $token = new AccessToken('jti1', 'client1', null, 'api', new DateTimeImmutable('+1 hour'));
        self::assertNull($token->identityId);
    }
}
