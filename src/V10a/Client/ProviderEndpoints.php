<?php

declare(strict_types=1);

/**
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\V10a\Client;

final class ProviderEndpoints
{
    public function __construct(
        public readonly string $requestTokenUrl,
        public readonly string $authorizeUrl,
        public readonly string $accessTokenUrl,
    ) {}
}
