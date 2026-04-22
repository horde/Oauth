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

final class Consent
{
    public function __construct(
        public readonly string $identityId,
        public readonly string $clientId,
        public readonly string $scope,
        public readonly DateTimeImmutable $grantedAt,
    ) {}

    public function coversScope(string $requestedScope): bool
    {
        $granted = array_filter(explode(' ', $this->scope));
        $requested = array_filter(explode(' ', $requestedScope));

        return array_diff($requested, $granted) === [];
    }
}
