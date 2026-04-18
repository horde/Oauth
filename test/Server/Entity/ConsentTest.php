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

use Horde\Oauth\Server\Entity\Consent;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use DateTimeImmutable;

#[CoversClass(Consent::class)]
final class ConsentTest extends TestCase
{
    public function testCoversScopeFull(): void
    {
        $consent = new Consent('user1', 'client1', 'openid profile email', new DateTimeImmutable());
        self::assertTrue($consent->coversScope('openid profile'));
        self::assertTrue($consent->coversScope('openid'));
    }

    public function testCoversScopePartial(): void
    {
        $consent = new Consent('user1', 'client1', 'openid profile', new DateTimeImmutable());
        self::assertFalse($consent->coversScope('openid profile email'));
    }

    public function testCoversScopeEmpty(): void
    {
        $consent = new Consent('user1', 'client1', 'openid', new DateTimeImmutable());
        self::assertTrue($consent->coversScope(''));
    }
}
