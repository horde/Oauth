<?php

declare(strict_types=1);

/**
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\Test\V10a\Signature;

use Horde\OAuth\V10a\Signature\HmacSha256;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(HmacSha256::class)]
final class HmacSha256Test extends TestCase
{
    public function testGetName(): void
    {
        self::assertSame('HMAC-SHA256', (new HmacSha256())->getName());
    }

    public function testSignProducesBase64(): void
    {
        $sig = (new HmacSha256())->sign('base-string', 'cs', 'ts');
        self::assertNotEmpty($sig);
        self::assertSame($sig, base64_encode(base64_decode($sig, true)));
    }

    public function testSignDifferentFromSha1(): void
    {
        $sha1 = (new \Horde\OAuth\V10a\Signature\HmacSha1())->sign('base', 'cs', 'ts');
        $sha256 = (new HmacSha256())->sign('base', 'cs', 'ts');
        self::assertNotSame($sha1, $sha256);
    }

    public function testVerifyRoundTrip(): void
    {
        $hmac = new HmacSha256();
        $sig = $hmac->sign('data', 'consumer', 'token');
        self::assertTrue($hmac->verify($sig, 'data', 'consumer', 'token'));
    }

    public function testVerifyRejectsInvalid(): void
    {
        self::assertFalse((new HmacSha256())->verify('bad', 'data', 'cs', 'ts'));
    }
}
