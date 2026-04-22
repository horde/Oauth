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

use Horde\OAuth\Server\Entity\AccessToken;

interface AccessTokenRepository
{
    public function persist(AccessToken $token): void;

    public function findById(string $tokenId): ?AccessToken;

    public function revoke(string $tokenId): void;

    public function isRevoked(string $tokenId): bool;
}
