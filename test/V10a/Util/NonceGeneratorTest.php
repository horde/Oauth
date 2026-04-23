<?php

declare(strict_types=1);

/**
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\Test\V10a\Util;

use Horde\OAuth\V10a\Util\NonceGenerator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(NonceGenerator::class)]
final class NonceGeneratorTest extends TestCase
{
    public function testGenerateReturnsHexString(): void
    {
        $nonce = NonceGenerator::generate();
        self::assertSame(32, strlen($nonce));
        self::assertMatchesRegularExpression('/\A[0-9a-f]{32}\z/', $nonce);
    }

    public function testGenerateReturnsUniqueValues(): void
    {
        $a = NonceGenerator::generate();
        $b = NonceGenerator::generate();
        self::assertNotSame($a, $b);
    }
}
