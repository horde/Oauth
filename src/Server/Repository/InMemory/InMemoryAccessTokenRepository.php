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

use Horde\Oauth\Server\Entity\AccessToken;
use Horde\Oauth\Server\Repository\AccessTokenRepository;

final class InMemoryAccessTokenRepository implements AccessTokenRepository
{
    /** @var array<string, AccessToken> */
    private array $tokens = [];

    public function persist(AccessToken $token): void
    {
        $this->tokens[$token->tokenId] = $token;
    }

    public function findById(string $tokenId): ?AccessToken
    {
        return $this->tokens[$tokenId] ?? null;
    }

    public function revoke(string $tokenId): void
    {
        $token = $this->tokens[$tokenId] ?? null;
        if ($token !== null) {
            $this->tokens[$tokenId] = new AccessToken(
                $token->tokenId,
                $token->clientId,
                $token->identityId,
                $token->scope,
                $token->expiresAt,
                revoked: true,
            );
        }
    }

    public function isRevoked(string $tokenId): bool
    {
        $token = $this->tokens[$tokenId] ?? null;
        return $token !== null && $token->revoked;
    }
}
