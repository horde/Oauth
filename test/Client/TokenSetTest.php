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

use Horde\Oauth\Client\TokenSet;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(TokenSet::class)]
final class TokenSetTest extends TestCase
{
    public function testFromArray(): void
    {
        $ts = TokenSet::fromArray([
            'access_token' => 'at1',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'refresh_token' => 'rt1',
            'scope' => 'openid',
            'id_token' => 'idt1',
        ]);
        self::assertSame('at1', $ts->accessToken);
        self::assertSame('Bearer', $ts->tokenType);
        self::assertSame(3600, $ts->expiresIn);
        self::assertSame('rt1', $ts->refreshToken);
        self::assertSame('openid', $ts->scope);
        self::assertSame('idt1', $ts->idToken);
        self::assertNotNull($ts->receivedAt);
    }

    public function testFromArrayDefaults(): void
    {
        $ts = TokenSet::fromArray(['access_token' => 'at1']);
        self::assertSame('Bearer', $ts->tokenType);
        self::assertNull($ts->expiresIn);
        self::assertNull($ts->refreshToken);
    }

    public function testIsExpired(): void
    {
        $ts = new TokenSet('at1', 'Bearer', 3600, receivedAt: time());
        self::assertFalse($ts->isExpired());
    }

    public function testIsExpiredTrue(): void
    {
        $ts = new TokenSet('at1', 'Bearer', 10, receivedAt: time() - 100);
        self::assertTrue($ts->isExpired());
    }

    public function testIsExpiredNoExpiry(): void
    {
        $ts = new TokenSet('at1', 'Bearer');
        self::assertFalse($ts->isExpired());
    }

    public function testGetExpiresAt(): void
    {
        $now = time();
        $ts = new TokenSet('at1', 'Bearer', 3600, receivedAt: $now);
        self::assertSame($now + 3600, $ts->getExpiresAt());
    }

    public function testToArray(): void
    {
        $ts = new TokenSet('at1', 'Bearer', 3600, 'rt1', 'openid', 'idt1');
        $arr = $ts->toArray();
        self::assertSame('at1', $arr['access_token']);
        self::assertArrayNotHasKey('receivedAt', $arr);
    }
}
