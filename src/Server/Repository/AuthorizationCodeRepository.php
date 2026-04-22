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

use Horde\OAuth\Server\Entity\AuthorizationCode;

interface AuthorizationCodeRepository
{
    public function persist(AuthorizationCode $code): void;

    public function findByCode(string $code): ?AuthorizationCode;

    public function markUsed(string $code): void;

    public function isUsed(string $code): bool;
}
