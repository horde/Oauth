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

namespace Horde\OAuth\Client;

use Horde\Jwt\Base64Url;

final class PkceGenerator
{
    public static function generateVerifier(int $length = 128): string
    {
        $length = max(43, min(128, $length));
        $bytes = random_bytes((int) ceil($length * 3 / 4));
        return substr(Base64Url::encode($bytes), 0, $length);
    }

    public static function computeChallenge(string $verifier, string $method = 'S256'): string
    {
        if ($method === 'plain') {
            return $verifier;
        }

        return Base64Url::encode(hash('sha256', $verifier, true));
    }
}
