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

use Horde\OAuth\Server\Entity\RefreshToken;

interface RefreshTokenRepository
{
    public function persist(RefreshToken $token): void;

    public function findById(string $tokenId): ?RefreshToken;

    public function revoke(string $tokenId): void;

    public function isRevoked(string $tokenId): bool;

    public function revokeByAccessTokenId(string $accessTokenId): void;
}
