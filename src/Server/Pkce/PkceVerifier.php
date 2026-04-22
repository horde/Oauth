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

namespace Horde\OAuth\Server\Pkce;

use Horde\Jwt\Base64Url;
use Horde\OAuth\Exception\InvalidRequestException;

final class PkceVerifier
{
    public static function verify(string $codeVerifier, string $codeChallenge, string $method): bool
    {
        if (!self::isValidMethod($method)) {
            throw new InvalidRequestException("Unsupported code_challenge_method: {$method}");
        }

        if ($method === 'S256') {
            $computed = Base64Url::encode(hash('sha256', $codeVerifier, true));
            return hash_equals($codeChallenge, $computed);
        }

        return hash_equals($codeChallenge, $codeVerifier);
    }

    public static function isValidMethod(string $method): bool
    {
        return in_array($method, ['S256', 'plain'], true);
    }
}
