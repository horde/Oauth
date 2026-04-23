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

namespace Horde\OAuth\Client;

/**
 * Result of an incremental consent check.
 *
 * When consentNeeded is false, the user already has all required scopes
 * and no redirect is necessary.
 */
final class IncrementalConsentResult
{
    public function __construct(
        public readonly string $authorizationUrl,
        public readonly bool $consentNeeded,
        public readonly ScopeSet $mergedScopes,
    ) {}
}
