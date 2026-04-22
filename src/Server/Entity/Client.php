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

final class Client
{
    /**
     * @param string[] $redirectUris
     * @param string[] $grantTypes
     */
    public function __construct(
        public readonly string $clientId,
        public readonly ?string $clientSecretHash,
        public readonly string $clientName,
        public readonly array $redirectUris,
        public readonly array $grantTypes,
        public readonly string $scope,
        public readonly string $clientType,
        public readonly string $tokenEndpointAuthMethod = 'client_secret_basic',
        public readonly ?DateTimeImmutable $createdAt = null,
        public readonly ?DateTimeImmutable $updatedAt = null,
    ) {}

    public function isConfidential(): bool
    {
        return $this->clientType === 'confidential';
    }

    public function isPublic(): bool
    {
        return $this->clientType === 'public';
    }

    public function supportsGrantType(string $grantType): bool
    {
        return in_array($grantType, $this->grantTypes, true);
    }

    public function hasRedirectUri(string $uri): bool
    {
        return in_array($uri, $this->redirectUris, true);
    }

    public function verifySecret(string $plainSecret): bool
    {
        if ($this->clientSecretHash === null) {
            return false;
        }

        return password_verify($plainSecret, $this->clientSecretHash);
    }

    /**
     * @return Scope[]
     */
    public function getDefaultScopes(): array
    {
        return Scope::fromSpaceSeparated($this->scope);
    }
}
