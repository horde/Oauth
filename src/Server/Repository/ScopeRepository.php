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

namespace Horde\OAuth\Server\Repository;

use Horde\OAuth\Server\Entity\Client;
use Horde\OAuth\Server\Entity\Scope;

interface ScopeRepository
{
    public function findByIdentifier(string $identifier): ?Scope;

    /**
     * @param Scope[] $scopes
     * @return Scope[]
     */
    public function finalizeScopes(
        array $scopes,
        string $grantType,
        Client $client,
        ?string $identityId = null,
    ): array;
}
