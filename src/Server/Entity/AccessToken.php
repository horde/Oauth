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

namespace Horde\Oauth\Server\Entity;

final class AccessToken
{
    public function __construct(
        public readonly string $tokenId,
        public readonly string $clientId,
        public readonly ?string $identityId,
        public readonly string $scope,
        public readonly \DateTimeImmutable $expiresAt,
        public readonly bool $revoked = false,
    ) {}

    public function isExpired(): bool
    {
        return new \DateTimeImmutable() >= $this->expiresAt;
    }

    public function isRevoked(): bool
    {
        return $this->revoked;
    }

    /**
     * @return Scope[]
     */
    public function getScopes(): array
    {
        return Scope::fromSpaceSeparated($this->scope);
    }
}
