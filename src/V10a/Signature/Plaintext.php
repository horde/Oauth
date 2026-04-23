<?php

declare(strict_types=1);

/**
 * Copyright 2008-2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\V10a\Signature;

use Horde\OAuth\V10a\Util\Rfc3986;

final class Plaintext implements SignatureMethod
{
    public function getName(): string
    {
        return 'PLAINTEXT';
    }

    public function sign(string $baseString, string $consumerSecret, string $tokenSecret): string
    {
        return Rfc3986::encode($consumerSecret) . '&' . Rfc3986::encode($tokenSecret);
    }

    public function verify(string $signature, string $baseString, string $consumerSecret, string $tokenSecret): bool
    {
        return hash_equals($signature, $this->sign($baseString, $consumerSecret, $tokenSecret));
    }
}
