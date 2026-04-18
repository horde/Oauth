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

use Horde\Oauth\Server\Entity\AuthorizationCode;
use Horde\Oauth\Server\Repository\InMemory\InMemoryAuthorizationCodeRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use DateTimeImmutable;

#[CoversClass(InMemoryAuthorizationCodeRepository::class)]
final class InMemoryAuthorizationCodeRepositoryTest extends TestCase
{
    public function testPersistAndFindByCode(): void
    {
        $repo = new InMemoryAuthorizationCodeRepository();
        $code = new AuthorizationCode(
            'code1',
            'c1',
            'u1',
            'https://example.com/cb',
            'openid',
            null,
            null,
            null,
            new DateTimeImmutable('+10 minutes'),
        );
        $repo->persist($code);
        self::assertSame($code, $repo->findByCode('code1'));
        self::assertNull($repo->findByCode('missing'));
    }

    public function testMarkUsedAndIsUsed(): void
    {
        $repo = new InMemoryAuthorizationCodeRepository();
        $code = new AuthorizationCode(
            'code1',
            'c1',
            'u1',
            'https://example.com/cb',
            'openid',
            null,
            null,
            null,
            new DateTimeImmutable('+10 minutes'),
        );
        $repo->persist($code);

        self::assertFalse($repo->isUsed('code1'));
        $repo->markUsed('code1');
        self::assertTrue($repo->isUsed('code1'));
        self::assertTrue($repo->findByCode('code1')->isUsed());
    }
}
