<?php

declare(strict_types=1);

/**
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\Test\V10a\Client;

use Horde\OAuth\V10a\Client\ConsumerCredentials;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ConsumerCredentials::class)]
final class ConsumerCredentialsTest extends TestCase
{
    public function testProperties(): void
    {
        $cred = new ConsumerCredentials('my-key', 'my-secret');
        self::assertSame('my-key', $cred->key);
        self::assertSame('my-secret', $cred->secret);
    }
}
