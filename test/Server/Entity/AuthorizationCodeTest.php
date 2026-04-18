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

namespace Horde\Oauth\Test\Server\Entity;

use Horde\Oauth\Server\Entity\AuthorizationCode;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use DateTimeImmutable;

#[CoversClass(AuthorizationCode::class)]
final class AuthorizationCodeTest extends TestCase
{
    public function testNotExpiredNotUsed(): void
    {
        $code = new AuthorizationCode(
            'abc123',
            'client1',
            'user1',
            'https://example.com/cb',
            'openid',
            null,
            null,
            null,
            new DateTimeImmutable('+10 minutes'),
        );
        self::assertFalse($code->isExpired());
        self::assertFalse($code->isUsed());
    }

    public function testExpired(): void
    {
        $code = new AuthorizationCode(
            'abc123',
            'client1',
            'user1',
            'https://example.com/cb',
            'openid',
            null,
            null,
            null,
            new DateTimeImmutable('-1 second'),
        );
        self::assertTrue($code->isExpired());
    }

    public function testUsed(): void
    {
        $code = new AuthorizationCode(
            'abc123',
            'client1',
            'user1',
            'https://example.com/cb',
            'openid',
            null,
            null,
            null,
            new DateTimeImmutable('+10 minutes'),
            used: true,
        );
        self::assertTrue($code->isUsed());
    }

    public function testPkceFields(): void
    {
        $code = new AuthorizationCode(
            'abc123',
            'client1',
            'user1',
            'https://example.com/cb',
            'openid',
            'challenge123',
            'S256',
            'nonce-val',
            new DateTimeImmutable('+10 minutes'),
        );
        self::assertSame('challenge123', $code->codeChallenge);
        self::assertSame('S256', $code->codeChallengeMethod);
        self::assertSame('nonce-val', $code->nonce);
    }
}
