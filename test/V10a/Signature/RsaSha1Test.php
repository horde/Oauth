<?php

declare(strict_types=1);

/**
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\Test\V10a\Signature;

use Horde\OAuth\V10a\Signature\RsaSha1;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(RsaSha1::class)]
final class RsaSha1Test extends TestCase
{
    private static function generateKeyPair(): array
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $details = openssl_pkey_get_details($key);
        $publicKey = openssl_pkey_get_public($details['key']);

        return [$key, $publicKey];
    }

    public function testGetName(): void
    {
        [$priv, $pub] = self::generateKeyPair();
        self::assertSame('RSA-SHA1', (new RsaSha1($priv, $pub))->getName());
    }

    public function testSignProducesBase64(): void
    {
        [$priv, $pub] = self::generateKeyPair();
        $sig = (new RsaSha1($priv, $pub))->sign('base-string', '', '');
        self::assertNotEmpty($sig);
        self::assertNotFalse(base64_decode($sig, true));
    }

    public function testSignIgnoresConsumerAndTokenSecrets(): void
    {
        [$priv, $pub] = self::generateKeyPair();
        $rsa = new RsaSha1($priv, $pub);
        $sig1 = $rsa->sign('same-base', 'cs1', 'ts1');
        $sig2 = $rsa->sign('same-base', 'cs2', 'ts2');
        self::assertSame($sig1, $sig2);
    }

    public function testVerifyAcceptsValidSignature(): void
    {
        [$priv, $pub] = self::generateKeyPair();
        $rsa = new RsaSha1($priv, $pub);
        $sig = $rsa->sign('the-data', '', '');
        self::assertTrue($rsa->verify($sig, 'the-data', '', ''));
    }

    public function testVerifyRejectsTamperedData(): void
    {
        [$priv, $pub] = self::generateKeyPair();
        $rsa = new RsaSha1($priv, $pub);
        $sig = $rsa->sign('original', '', '');
        self::assertFalse($rsa->verify($sig, 'tampered', '', ''));
    }

    public function testVerifyRejectsInvalidBase64(): void
    {
        [$priv, $pub] = self::generateKeyPair();
        $rsa = new RsaSha1($priv, $pub);
        self::assertFalse($rsa->verify('not-valid-base64!!!', 'data', '', ''));
    }

    public function testVerifyRejectsDifferentKeyPair(): void
    {
        [$priv1, $pub1] = self::generateKeyPair();
        [$priv2, $pub2] = self::generateKeyPair();

        $signer = new RsaSha1($priv1, $pub1);
        $verifier = new RsaSha1($priv2, $pub2);

        $sig = $signer->sign('data', '', '');
        self::assertFalse($verifier->verify($sig, 'data', '', ''));
    }
}
