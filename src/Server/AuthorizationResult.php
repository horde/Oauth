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

namespace Horde\Oauth\Server;

use Horde\Oauth\Server\Entity\Scope;

final class AuthorizationResult
{
    /**
     * @param Scope[]|null $approvedScopes
     */
    public function __construct(
        public readonly AuthorizationRequest $request,
        public readonly bool $approved,
        public readonly ?string $identityId,
        public readonly ?array $approvedScopes = null,
    ) {}
}
