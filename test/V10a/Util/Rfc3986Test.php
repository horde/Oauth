<?php

declare(strict_types=1);

/**
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\Test\V10a\Util;

use Horde\OAuth\V10a\Util\Rfc3986;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(Rfc3986::class)]
final class Rfc3986Test extends TestCase
{
    /**
     * @return array<string, array{string, string}>
     */
    public static function encodingProvider(): array
    {
        return [
            'empty string' => ['', ''],
            'plain ascii' => ['foobar', 'foobar'],
            'space' => ['hello world', 'hello%20world'],
            'tilde preserved' => ['~user', '~user'],
            'plus encoded' => ['a+b', 'a%2Bb'],
            'slash encoded' => ['a/b', 'a%2Fb'],
            'rfc5849 example key' => ['djr9pjt0jw9djfk203', 'djr9pjt0jw9djfk203'],
            'special chars' => ['Ladies + Gentlemen', 'Ladies%20%2B%20Gentlemen'],
            'exclamation' => ['An encoded string!', 'An%20encoded%20string%21'],
            'percent' => ['100%', '100%25'],
        ];
    }

    #[DataProvider('encodingProvider')]
    public function testEncode(string $input, string $expected): void
    {
        self::assertSame($expected, Rfc3986::encode($input));
    }
}
