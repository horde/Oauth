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

namespace Horde\OAuth\Test\Server\Repository\InMemory;

use Horde\OAuth\Server\Entity\Client;
use Horde\OAuth\Server\Entity\Scope;
use Horde\OAuth\Server\Repository\InMemory\InMemoryScopeRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(InMemoryScopeRepository::class)]
final class InMemoryScopeRepositoryTest extends TestCase
{
    public function testFindByIdentifier(): void
    {
        $repo = new InMemoryScopeRepository(new Scope('openid'), new Scope('profile'));
        self::assertNotNull($repo->findByIdentifier('openid'));
        self::assertNull($repo->findByIdentifier('email'));
    }

    public function testFinalizeScopesFiltersUnknown(): void
    {
        $repo = new InMemoryScopeRepository(new Scope('openid'), new Scope('profile'));
        $client = new Client('c1', null, 'Test', [], ['authorization_code'], 'openid', 'public');
        $requested = [new Scope('openid'), new Scope('admin')];
        $result = $repo->finalizeScopes($requested, 'authorization_code', $client);
        self::assertCount(1, $result);
        self::assertSame('openid', $result[0]->identifier);
    }

    public function testFinalizeScopesDefaultsWhenEmpty(): void
    {
        $repo = new InMemoryScopeRepository(new Scope('openid'), new Scope('profile'));
        $client = new Client('c1', null, 'Test', [], ['authorization_code'], 'openid profile', 'public');
        $result = $repo->finalizeScopes([], 'authorization_code', $client);
        self::assertCount(2, $result);
    }
}
