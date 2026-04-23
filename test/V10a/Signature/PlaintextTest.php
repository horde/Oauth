<?php

declare(strict_types=1);

/**
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\Test\V10a\Signature;

use Horde\OAuth\V10a\Signature\Plaintext;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Plaintext::class)]
final class PlaintextTest extends TestCase
{
    public function testGetName(): void
    {
        self::assertSame('PLAINTEXT', (new Plaintext())->getName());
    }

    public function testSignIgnoresBaseString(): void
    {
        $pt = new Plaintext();
        $sig1 = $pt->sign('anything', 'cs', 'ts');
        $sig2 = $pt->sign('completely-different', 'cs', 'ts');
        self::assertSame($sig1, $sig2);
    }

    public function testSignConcatenatesSecrets(): void
    {
        $sig = (new Plaintext())->sign('ignored', 'consumer-secret', 'token-secret');
        self::assertSame('consumer-secret&token-secret', $sig);
    }

    public function testSignEncodesSpecialChars(): void
    {
        $sig = (new Plaintext())->sign('ignored', 'sec&ret', 'tok/en');
        self::assertSame('sec%26ret&tok%2Fen', $sig);
    }

    public function testSignWithEmptyTokenSecret(): void
    {
        $sig = (new Plaintext())->sign('ignored', 'consumer', '');
        self::assertSame('consumer&', $sig);
    }

    public function testVerifyRoundTrip(): void
    {
        $pt = new Plaintext();
        $sig = $pt->sign('ignored', 'cs', 'ts');
        self::assertTrue($pt->verify($sig, 'also-ignored', 'cs', 'ts'));
    }

    public function testVerifyRejectsWrongSecret(): void
    {
        $pt = new Plaintext();
        $sig = $pt->sign('ignored', 'cs', 'ts');
        self::assertFalse($pt->verify($sig, 'ignored', 'cs', 'wrong'));
    }
}
