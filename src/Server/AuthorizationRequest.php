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

namespace Horde\Oauth\Server;

use Horde\Oauth\Server\Entity\Client;
use Horde\Oauth\Server\Entity\Scope;

final class AuthorizationRequest
{
    /**
     * @param Scope[] $scopes
     */
    public function __construct(
        public readonly Client $client,
        public readonly string $responseType,
        public readonly string $redirectUri,
        public readonly string $state,
        public readonly array $scopes,
        public readonly ?string $codeChallenge,
        public readonly ?string $codeChallengeMethod,
        public readonly ?string $nonce,
    ) {}
}
