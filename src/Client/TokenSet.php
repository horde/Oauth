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

namespace Horde\Oauth\Client;

final class TokenSet
{
    public function __construct(
        public readonly string $accessToken,
        public readonly string $tokenType,
        public readonly ?int $expiresIn = null,
        public readonly ?string $refreshToken = null,
        public readonly ?string $scope = null,
        public readonly ?string $idToken = null,
        public readonly ?int $receivedAt = null,
    ) {}

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            accessToken: (string) ($data['access_token'] ?? ''),
            tokenType: (string) ($data['token_type'] ?? 'Bearer'),
            expiresIn: isset($data['expires_in']) ? (int) $data['expires_in'] : null,
            refreshToken: isset($data['refresh_token']) ? (string) $data['refresh_token'] : null,
            scope: isset($data['scope']) ? (string) $data['scope'] : null,
            idToken: isset($data['id_token']) ? (string) $data['id_token'] : null,
            receivedAt: time(),
        );
    }

    public function isExpired(int $leeway = 30): bool
    {
        $expiresAt = $this->getExpiresAt();
        if ($expiresAt === null) {
            return false;
        }

        return time() >= ($expiresAt - $leeway);
    }

    public function getExpiresAt(): ?int
    {
        if ($this->expiresIn === null || $this->receivedAt === null) {
            return null;
        }

        return $this->receivedAt + $this->expiresIn;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return array_filter([
            'access_token' => $this->accessToken,
            'token_type' => $this->tokenType,
            'expires_in' => $this->expiresIn,
            'refresh_token' => $this->refreshToken,
            'scope' => $this->scope,
            'id_token' => $this->idToken,
        ], static fn($v) => $v !== null);
    }
}
