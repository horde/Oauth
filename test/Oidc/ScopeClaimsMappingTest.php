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

namespace Horde\Oauth\Test\Oidc;

use Horde\Oauth\Oidc\ScopeClaimsMapping;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ScopeClaimsMapping::class)]
final class ScopeClaimsMappingTest extends TestCase
{
    public function testDefaultProfileClaims(): void
    {
        $mapping = new ScopeClaimsMapping();
        $claims = $mapping->getClaimsForScopes(['profile']);
        self::assertContains('name', $claims);
        self::assertContains('family_name', $claims);
        self::assertContains('given_name', $claims);
        self::assertContains('preferred_username', $claims);
    }

    public function testDefaultEmailClaims(): void
    {
        $mapping = new ScopeClaimsMapping();
        $claims = $mapping->getClaimsForScopes(['email']);
        self::assertSame(['email', 'email_verified'], $claims);
    }

    public function testMultipleScopes(): void
    {
        $mapping = new ScopeClaimsMapping();
        $claims = $mapping->getClaimsForScopes(['profile', 'email']);
        self::assertContains('name', $claims);
        self::assertContains('email', $claims);
    }

    public function testUnknownScopeReturnsEmpty(): void
    {
        $mapping = new ScopeClaimsMapping();
        self::assertSame([], $mapping->getClaimsForScopes(['openid']));
    }

    public function testCustomMapping(): void
    {
        $mapping = new ScopeClaimsMapping(['custom' => ['role', 'department']]);
        $claims = $mapping->getClaimsForScopes(['custom']);
        self::assertSame(['role', 'department'], $claims);
        self::assertSame([], $mapping->getClaimsForScopes(['profile']));
    }

    public function testGetScopesForClaim(): void
    {
        $mapping = new ScopeClaimsMapping();
        self::assertSame(['email'], $mapping->getScopesForClaim('email'));
        self::assertSame(['profile'], $mapping->getScopesForClaim('name'));
        self::assertSame([], $mapping->getScopesForClaim('nonexistent'));
    }

    public function testDeduplication(): void
    {
        $mapping = new ScopeClaimsMapping([
            'a' => ['x', 'y'],
            'b' => ['y', 'z'],
        ]);
        $claims = $mapping->getClaimsForScopes(['a', 'b']);
        self::assertCount(3, $claims);
    }
}
