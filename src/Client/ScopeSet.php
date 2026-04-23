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
 * Immutable set of OAuth2 scope strings (RFC 6749, space-separated).
 */
final class ScopeSet
{
    /** @var string[] */
    private readonly array $scopes;

    public function __construct(string ...$scopes)
    {
        $unique = array_values(array_unique(array_filter($scopes, static fn(string $s) => $s !== '')));
        sort($unique);
        $this->scopes = $unique;
    }

    public static function fromSpaceSeparated(?string $scopeString): self
    {
        if ($scopeString === null || $scopeString === '') {
            return new self();
        }

        return new self(...preg_split('/\s+/', $scopeString));
    }

    public function has(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }

    public function hasAll(self $required): bool
    {
        foreach ($required->scopes as $scope) {
            if (!$this->has($scope)) {
                return false;
            }
        }

        return true;
    }

    public function union(self $other): self
    {
        return new self(...$this->scopes, ...$other->scopes);
    }

    public function diff(self $other): self
    {
        $remaining = array_filter(
            $this->scopes,
            static fn(string $s) => !$other->has($s),
        );

        return new self(...$remaining);
    }

    /**
     * @return string[]
     */
    public function toArray(): array
    {
        return $this->scopes;
    }

    public function toSpaceSeparated(): string
    {
        return implode(' ', $this->scopes);
    }

    public function isEmpty(): bool
    {
        return $this->scopes === [];
    }

    public function count(): int
    {
        return count($this->scopes);
    }
}
