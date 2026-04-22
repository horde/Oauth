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

final class Scope
{
    public function __construct(
        public readonly string $identifier,
    ) {}

    public function __toString(): string
    {
        return $this->identifier;
    }

    public static function fromString(string $scope): self
    {
        return new self(trim($scope));
    }

    /**
     * @return self[]
     */
    public static function fromSpaceSeparated(string $scopes): array
    {
        if (trim($scopes) === '') {
            return [];
        }

        return array_map(
            static fn(string $s) => new self(trim($s)),
            explode(' ', $scopes),
        );
    }

    /**
     * @param self[] $scopes
     */
    public static function toSpaceSeparated(array $scopes): string
    {
        return implode(' ', array_map(
            static fn(self $s) => $s->identifier,
            $scopes,
        ));
    }
}
