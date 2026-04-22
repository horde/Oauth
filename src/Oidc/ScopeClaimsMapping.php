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

namespace Horde\OAuth\Oidc;

final class ScopeClaimsMapping
{
    private const DEFAULTS = [
        'profile' => [
            'name', 'family_name', 'given_name', 'middle_name', 'nickname',
            'preferred_username', 'profile', 'picture', 'website',
            'gender', 'birthdate', 'zoneinfo', 'locale', 'updated_at',
        ],
        'email' => ['email', 'email_verified'],
        'address' => ['address'],
        'phone' => ['phone_number', 'phone_number_verified'],
    ];

    /** @var array<string, string[]> */
    private readonly array $mapping;

    /**
     * @param array<string, string[]> $mapping
     */
    public function __construct(array $mapping = [])
    {
        $this->mapping = $mapping !== [] ? $mapping : self::DEFAULTS;
    }

    /**
     * @param string[] $scopes
     * @return string[]
     */
    public function getClaimsForScopes(array $scopes): array
    {
        $claims = [];
        foreach ($scopes as $scope) {
            if (isset($this->mapping[$scope])) {
                $claims = array_merge($claims, $this->mapping[$scope]);
            }
        }
        return array_unique($claims);
    }

    /**
     * @return string[]
     */
    public function getScopesForClaim(string $claim): array
    {
        $scopes = [];
        foreach ($this->mapping as $scope => $claims) {
            if (in_array($claim, $claims, true)) {
                $scopes[] = $scope;
            }
        }
        return $scopes;
    }
}
