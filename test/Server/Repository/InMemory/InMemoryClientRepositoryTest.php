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

use Horde\Oauth\Server\Entity\Client;
use Horde\Oauth\Server\Repository\InMemory\InMemoryClientRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(InMemoryClientRepository::class)]
final class InMemoryClientRepositoryTest extends TestCase
{
    private function makeClient(string $id = 'c1', string $type = 'confidential'): Client
    {
        return new Client(
            $id,
            $type === 'confidential' ? password_hash('s', PASSWORD_BCRYPT) : null,
            'Test',
            ['https://example.com/cb'],
            ['authorization_code'],
            'openid',
            $type,
        );
    }

    public function testFindById(): void
    {
        $repo = new InMemoryClientRepository($this->makeClient('c1'));
        self::assertNotNull($repo->findById('c1'));
        self::assertNull($repo->findById('c2'));
    }

    public function testValidateClient(): void
    {
        $repo = new InMemoryClientRepository($this->makeClient('c1'));
        self::assertTrue($repo->validateClient('c1', 's', 'authorization_code'));
        self::assertFalse($repo->validateClient('c1', 'wrong', 'authorization_code'));
        self::assertFalse($repo->validateClient('c1', 's', 'client_credentials'));
        self::assertFalse($repo->validateClient('missing', 's', 'authorization_code'));
    }

    public function testValidatePublicClient(): void
    {
        $repo = new InMemoryClientRepository($this->makeClient('pub', 'public'));
        self::assertTrue($repo->validateClient('pub', null, 'authorization_code'));
    }
}
