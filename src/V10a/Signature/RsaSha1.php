<?php

declare(strict_types=1);

/**
 * Copyright 2008-2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\V10a\Signature;

use Horde\OAuth\Exception\OAuthException;
use OpenSSLAsymmetricKey;

final class RsaSha1 implements SignatureMethod
{
    public function __construct(
        private readonly OpenSSLAsymmetricKey $privateKey,
        private readonly OpenSSLAsymmetricKey $publicKey,
    ) {}

    public function getName(): string
    {
        return 'RSA-SHA1';
    }

    public function sign(string $baseString, string $consumerSecret, string $tokenSecret): string
    {
        $ok = openssl_sign($baseString, $signature, $this->privateKey, OPENSSL_ALGO_SHA1);

        if (!$ok) {
            throw new OAuthException('signature_error', 'RSA-SHA1 signing failed: ' . (openssl_error_string() ?: 'unknown'));
        }

        return base64_encode($signature);
    }

    public function verify(string $signature, string $baseString, string $consumerSecret, string $tokenSecret): bool
    {
        $decoded = base64_decode($signature, true);

        if ($decoded === false) {
            return false;
        }

        return openssl_verify($baseString, $decoded, $this->publicKey, OPENSSL_ALGO_SHA1) === 1;
    }
}
