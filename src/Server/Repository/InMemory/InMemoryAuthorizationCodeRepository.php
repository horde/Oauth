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

use Horde\Oauth\Server\Entity\AuthorizationCode;
use Horde\Oauth\Server\Repository\AuthorizationCodeRepository;

final class InMemoryAuthorizationCodeRepository implements AuthorizationCodeRepository
{
    /** @var array<string, AuthorizationCode> */
    private array $codes = [];

    public function persist(AuthorizationCode $code): void
    {
        $this->codes[$code->code] = $code;
    }

    public function findByCode(string $code): ?AuthorizationCode
    {
        return $this->codes[$code] ?? null;
    }

    public function markUsed(string $code): void
    {
        $existing = $this->codes[$code] ?? null;
        if ($existing !== null) {
            $this->codes[$code] = new AuthorizationCode(
                $existing->code,
                $existing->clientId,
                $existing->identityId,
                $existing->redirectUri,
                $existing->scope,
                $existing->codeChallenge,
                $existing->codeChallengeMethod,
                $existing->nonce,
                $existing->expiresAt,
                used: true,
            );
        }
    }

    public function isUsed(string $code): bool
    {
        $existing = $this->codes[$code] ?? null;
        return $existing !== null && $existing->used;
    }
}
