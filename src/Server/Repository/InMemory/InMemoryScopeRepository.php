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

namespace Horde\Oauth\Server\Repository\InMemory;

use Horde\Oauth\Server\Entity\Client;
use Horde\Oauth\Server\Entity\Scope;
use Horde\Oauth\Server\Repository\ScopeRepository;

final class InMemoryScopeRepository implements ScopeRepository
{
    /** @var array<string, Scope> */
    private array $scopes = [];

    public function __construct(Scope ...$scopes)
    {
        foreach ($scopes as $scope) {
            $this->scopes[$scope->identifier] = $scope;
        }
    }

    public function findByIdentifier(string $identifier): ?Scope
    {
        return $this->scopes[$identifier] ?? null;
    }

    public function finalizeScopes(
        array $scopes,
        string $grantType,
        Client $client,
        ?string $identityId = null,
    ): array {
        if ($scopes === []) {
            return $client->getDefaultScopes();
        }

        return array_values(array_filter(
            $scopes,
            fn(Scope $scope) => isset($this->scopes[$scope->identifier]),
        ));
    }
}
