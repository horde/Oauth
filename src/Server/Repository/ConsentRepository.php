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

use Horde\OAuth\Server\Entity\Consent;

interface ConsentRepository
{
    public function findConsent(string $identityId, string $clientId): ?Consent;

    public function persist(Consent $consent): void;

    public function revoke(string $identityId, string $clientId): void;
}
