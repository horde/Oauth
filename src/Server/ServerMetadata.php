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

namespace Horde\OAuth\Server;

final class ServerMetadata
{
    /**
     * @param string[] $scopesSupported
     * @param string[] $responseTypesSupported
     * @param string[] $grantTypesSupported
     * @param string[] $tokenEndpointAuthMethodsSupported
     * @param string[] $codeChallengeMethodsSupported
     * @param string[] $subjectTypesSupported
     * @param string[] $idTokenSigningAlgValuesSupported
     */
    public function __construct(
        public readonly string $issuer,
        public readonly string $authorizationEndpoint,
        public readonly string $tokenEndpoint,
        public readonly ?string $revocationEndpoint = null,
        public readonly ?string $introspectionEndpoint = null,
        public readonly ?string $jwksUri = null,
        public readonly ?string $userinfoEndpoint = null,
        public readonly array $scopesSupported = [],
        public readonly array $responseTypesSupported = ['code'],
        public readonly array $grantTypesSupported = ['authorization_code', 'client_credentials', 'refresh_token'],
        public readonly array $tokenEndpointAuthMethodsSupported = ['client_secret_basic', 'client_secret_post'],
        public readonly array $codeChallengeMethodsSupported = ['S256'],
        public readonly array $subjectTypesSupported = ['public'],
        public readonly array $idTokenSigningAlgValuesSupported = ['RS256'],
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $data = [
            'issuer' => $this->issuer,
            'authorization_endpoint' => $this->authorizationEndpoint,
            'token_endpoint' => $this->tokenEndpoint,
        ];

        if ($this->revocationEndpoint !== null) {
            $data['revocation_endpoint'] = $this->revocationEndpoint;
        }
        if ($this->introspectionEndpoint !== null) {
            $data['introspection_endpoint'] = $this->introspectionEndpoint;
        }
        if ($this->jwksUri !== null) {
            $data['jwks_uri'] = $this->jwksUri;
        }
        if ($this->userinfoEndpoint !== null) {
            $data['userinfo_endpoint'] = $this->userinfoEndpoint;
        }

        $data['scopes_supported'] = $this->scopesSupported;
        $data['response_types_supported'] = $this->responseTypesSupported;
        $data['grant_types_supported'] = $this->grantTypesSupported;
        $data['token_endpoint_auth_methods_supported'] = $this->tokenEndpointAuthMethodsSupported;
        $data['code_challenge_methods_supported'] = $this->codeChallengeMethodsSupported;
        $data['subject_types_supported'] = $this->subjectTypesSupported;
        $data['id_token_signing_alg_values_supported'] = $this->idTokenSigningAlgValuesSupported;

        return $data;
    }

    public function toJson(): string
    {
        return json_encode($this->toArray(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
}
