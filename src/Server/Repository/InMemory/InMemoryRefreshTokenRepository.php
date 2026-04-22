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

namespace Horde\OAuth\Server\Repository\InMemory;

use Horde\OAuth\Server\Entity\RefreshToken;
use Horde\OAuth\Server\Repository\RefreshTokenRepository;

final class InMemoryRefreshTokenRepository implements RefreshTokenRepository
{
    /** @var array<string, RefreshToken> */
    private array $tokens = [];

    public function persist(RefreshToken $token): void
    {
        $this->tokens[$token->tokenId] = $token;
    }

    public function findById(string $tokenId): ?RefreshToken
    {
        return $this->tokens[$tokenId] ?? null;
    }

    public function revoke(string $tokenId): void
    {
        $token = $this->tokens[$tokenId] ?? null;
        if ($token !== null) {
            $this->tokens[$tokenId] = new RefreshToken(
                $token->tokenId,
                $token->accessTokenId,
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

    public function revokeByAccessTokenId(string $accessTokenId): void
    {
        foreach ($this->tokens as $id => $token) {
            if ($token->accessTokenId === $accessTokenId) {
                $this->revoke($id);
            }
        }
    }
}
