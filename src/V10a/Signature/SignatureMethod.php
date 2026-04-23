<?php

declare(strict_types=1);

/**
 * Copyright 2008-2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\V10a\Signature;

interface SignatureMethod
{
    public function getName(): string;

    public function sign(string $baseString, string $consumerSecret, string $tokenSecret): string;

    public function verify(string $signature, string $baseString, string $consumerSecret, string $tokenSecret): bool;
}
