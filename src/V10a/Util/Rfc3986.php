<?php

declare(strict_types=1);

/**
 * Copyright 2008-2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\V10a\Util;

final class Rfc3986
{
    public static function encode(string $value): string
    {
        return str_replace(['%7E', '+'], ['~', '%2B'], rawurlencode($value));
    }
}
