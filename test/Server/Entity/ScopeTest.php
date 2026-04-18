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

use Horde\Oauth\Server\Entity\Scope;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Scope::class)]
final class ScopeTest extends TestCase
{
    public function testConstructAndToString(): void
    {
        $scope = new Scope('openid');
        self::assertSame('openid', $scope->identifier);
        self::assertSame('openid', (string) $scope);
    }

    public function testFromString(): void
    {
        $scope = Scope::fromString('  email ');
        self::assertSame('email', $scope->identifier);
    }

    public function testFromSpaceSeparated(): void
    {
        $scopes = Scope::fromSpaceSeparated('openid profile email');
        self::assertCount(3, $scopes);
        self::assertSame('openid', $scopes[0]->identifier);
        self::assertSame('profile', $scopes[1]->identifier);
        self::assertSame('email', $scopes[2]->identifier);
    }

    public function testFromSpaceSeparatedEmpty(): void
    {
        self::assertSame([], Scope::fromSpaceSeparated(''));
        self::assertSame([], Scope::fromSpaceSeparated('   '));
    }

    public function testToSpaceSeparated(): void
    {
        $scopes = [new Scope('openid'), new Scope('profile')];
        self::assertSame('openid profile', Scope::toSpaceSeparated($scopes));
    }

    public function testToSpaceSeparatedEmpty(): void
    {
        self::assertSame('', Scope::toSpaceSeparated([]));
    }
}
