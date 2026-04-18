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

use Horde\Oauth\Server\Entity\Consent;
use Horde\Oauth\Server\Repository\ConsentRepository;

final class InMemoryConsentRepository implements ConsentRepository
{
    /** @var array<string, Consent> */
    private array $consents = [];

    public function findConsent(string $identityId, string $clientId): ?Consent
    {
        return $this->consents[$this->key($identityId, $clientId)] ?? null;
    }

    public function persist(Consent $consent): void
    {
        $this->consents[$this->key($consent->identityId, $consent->clientId)] = $consent;
    }

    public function revoke(string $identityId, string $clientId): void
    {
        unset($this->consents[$this->key($identityId, $clientId)]);
    }

    private function key(string $identityId, string $clientId): string
    {
        return "{$identityId}:{$clientId}";
    }
}
