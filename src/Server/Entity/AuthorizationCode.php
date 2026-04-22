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

namespace Horde\OAuth\Server\Entity;

use DateTimeImmutable;

final class AuthorizationCode
{
    public function __construct(
        public readonly string $code,
        public readonly string $clientId,
        public readonly string $identityId,
        public readonly string $redirectUri,
        public readonly string $scope,
        public readonly ?string $codeChallenge,
        public readonly ?string $codeChallengeMethod,
        public readonly ?string $nonce,
        public readonly DateTimeImmutable $expiresAt,
        public readonly bool $used = false,
    ) {}

    public function isExpired(): bool
    {
        return new DateTimeImmutable() >= $this->expiresAt;
    }

    public function isUsed(): bool
    {
        return $this->used;
    }
}
