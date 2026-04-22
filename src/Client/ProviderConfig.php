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

final class ProviderConfig
{
    /**
     * @param string[] $scopesSupported
     * @param string[] $responseTypesSupported
     * @param string[] $grantTypesSupported
     * @param string[] $tokenEndpointAuthMethodsSupported
     * @param string[] $idTokenSigningAlgValuesSupported
     */
    public function __construct(
        public readonly string $issuer,
        public readonly string $authorizationEndpoint,
        public readonly string $tokenEndpoint,
        public readonly ?string $userinfoEndpoint = null,
        public readonly ?string $jwksUri = null,
        public readonly ?string $revocationEndpoint = null,
        public readonly ?string $introspectionEndpoint = null,
        public readonly array $scopesSupported = [],
        public readonly array $responseTypesSupported = ['code'],
        public readonly array $grantTypesSupported = [],
        public readonly array $tokenEndpointAuthMethodsSupported = ['client_secret_basic'],
        public readonly array $idTokenSigningAlgValuesSupported = [],
    ) {}

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            issuer: (string) ($data['issuer'] ?? ''),
            authorizationEndpoint: (string) ($data['authorization_endpoint'] ?? ''),
            tokenEndpoint: (string) ($data['token_endpoint'] ?? ''),
            userinfoEndpoint: isset($data['userinfo_endpoint']) ? (string) $data['userinfo_endpoint'] : null,
            jwksUri: isset($data['jwks_uri']) ? (string) $data['jwks_uri'] : null,
            revocationEndpoint: isset($data['revocation_endpoint']) ? (string) $data['revocation_endpoint'] : null,
            introspectionEndpoint: isset($data['introspection_endpoint']) ? (string) $data['introspection_endpoint'] : null,
            scopesSupported: (array) ($data['scopes_supported'] ?? []),
            responseTypesSupported: (array) ($data['response_types_supported'] ?? ['code']),
            grantTypesSupported: (array) ($data['grant_types_supported'] ?? []),
            tokenEndpointAuthMethodsSupported: (array) ($data['token_endpoint_auth_methods_supported'] ?? ['client_secret_basic']),
            idTokenSigningAlgValuesSupported: (array) ($data['id_token_signing_alg_values_supported'] ?? []),
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return array_filter([
            'issuer' => $this->issuer,
            'authorization_endpoint' => $this->authorizationEndpoint,
            'token_endpoint' => $this->tokenEndpoint,
            'userinfo_endpoint' => $this->userinfoEndpoint,
            'jwks_uri' => $this->jwksUri,
            'revocation_endpoint' => $this->revocationEndpoint,
            'introspection_endpoint' => $this->introspectionEndpoint,
            'scopes_supported' => $this->scopesSupported,
            'response_types_supported' => $this->responseTypesSupported,
            'grant_types_supported' => $this->grantTypesSupported,
            'token_endpoint_auth_methods_supported' => $this->tokenEndpointAuthMethodsSupported,
            'id_token_signing_alg_values_supported' => $this->idTokenSigningAlgValuesSupported,
        ], static fn($v) => $v !== null && $v !== []);
    }
}
