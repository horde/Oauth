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

namespace Horde\OAuth\Server\Token;

use Horde\OAuth\Server\Entity\Client;
use Horde\OAuth\Server\Entity\RefreshToken;
use Horde\OAuth\Server\Entity\Scope;
use Horde\OAuth\Server\Repository\RefreshTokenRepository;
use DateTimeImmutable;

final class RefreshTokenIssuer
{
    public function __construct(
        private readonly RefreshTokenRepository $repository,
        private readonly int $ttl = 2592000,
    ) {}

    /**
     * @param Scope[] $scopes
     */
    public function issue(string $accessTokenId, Client $client, ?string $identityId, array $scopes): string
    {
        $tokenId = bin2hex(random_bytes(32));
        $expiresAt = new DateTimeImmutable("+{$this->ttl} seconds");

        $entity = new RefreshToken(
            $tokenId,
            $accessTokenId,
            $client->clientId,
            $identityId,
            Scope::toSpaceSeparated($scopes),
            $expiresAt,
        );
        $this->repository->persist($entity);

        return $tokenId;
    }
}
