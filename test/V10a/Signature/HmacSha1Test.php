<?php

declare(strict_types=1);

/**
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\Test\V10a\Signature;

use Horde\OAuth\V10a\Signature\HmacSha1;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(HmacSha1::class)]
final class HmacSha1Test extends TestCase
{
    public function testGetName(): void
    {
        self::assertSame('HMAC-SHA1', (new HmacSha1())->getName());
    }

    public function testSignProducesBase64(): void
    {
        $sig = (new HmacSha1())->sign('base-string', 'consumer-secret', 'token-secret');
        self::assertNotEmpty($sig);
        self::assertSame($sig, base64_encode(base64_decode($sig, true)));
    }

    public function testSignWithEmptyTokenSecret(): void
    {
        $sig = (new HmacSha1())->sign('base-string', 'consumer-secret', '');
        self::assertNotEmpty($sig);
    }

    /**
     * RFC 5849 Section 1.2 example (reconstructed).
     * Base string, consumer secret and token secret are known; verify the signature matches.
     */
    public function testSignDeterministic(): void
    {
        $hmac = new HmacSha1();
        $sig1 = $hmac->sign('GET&http%3A%2F%2Fexample.com&foo%3Dbar', 'cs', 'ts');
        $sig2 = $hmac->sign('GET&http%3A%2F%2Fexample.com&foo%3Dbar', 'cs', 'ts');
        self::assertSame($sig1, $sig2);
    }

    public function testVerifyAcceptsValidSignature(): void
    {
        $hmac = new HmacSha1();
        $sig = $hmac->sign('the-base-string', 'cs', 'ts');
        self::assertTrue($hmac->verify($sig, 'the-base-string', 'cs', 'ts'));
    }

    public function testVerifyRejectsInvalidSignature(): void
    {
        $hmac = new HmacSha1();
        self::assertFalse($hmac->verify('invalid', 'the-base-string', 'cs', 'ts'));
    }

    public function testVerifyRejectsTamperedBaseString(): void
    {
        $hmac = new HmacSha1();
        $sig = $hmac->sign('original', 'cs', 'ts');
        self::assertFalse($hmac->verify($sig, 'tampered', 'cs', 'ts'));
    }

    public function testKeyConstructionEncodesSecrets(): void
    {
        $hmac = new HmacSha1();
        $sigPlain = $hmac->sign('base', 'secret', '');
        $sigSpecial = $hmac->sign('base', 'sec&ret', '');
        self::assertNotSame($sigPlain, $sigSpecial);
    }
}
