<?php

declare(strict_types=1);

/**
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\V10a\Request;

use Horde\OAuth\V10a\Util\Rfc3986;

final class AuthorizationHeader
{
    /**
     * @param array<string, string> $oauthParams
     */
    public static function build(array $oauthParams, string $realm = ''): string
    {
        $parts = [];

        if ($realm !== '') {
            $parts[] = 'realm="' . Rfc3986::encode($realm) . '"';
        }

        foreach ($oauthParams as $key => $value) {
            if (str_starts_with($key, 'oauth_')) {
                $parts[] = Rfc3986::encode($key) . '="' . Rfc3986::encode($value) . '"';
            }
        }

        return 'OAuth ' . implode(', ', $parts);
    }
}
