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

use Horde\Jwt\Key\PublicKey;
use Horde\Jwt\Signer\SignerInterface;
use Horde\Jwt\TokenEncoder;
use Horde\OAuth\Oidc\Handler\DiscoveryEndpoint;
use Horde\OAuth\Oidc\Handler\JwksEndpoint;
use Horde\OAuth\Oidc\Handler\UserinfoEndpoint;
use Horde\OAuth\Server\AuthorizationServer;
use Horde\OAuth\Server\ServerMetadata;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

final class OidcServer
{
    public function __construct(
        private readonly AuthorizationServer $server,
        private readonly IdTokenBuilder $idTokenBuilder,
        private readonly ClaimsMapper $claimsMapper,
        private readonly ScopeClaimsMapping $scopeMapping,
        private readonly PublicKey $publicKey,
        private readonly ServerMetadata $metadata,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly StreamFactoryInterface $streamFactory,
    ) {}

    public function getDiscoveryEndpoint(): DiscoveryEndpoint
    {
        return new DiscoveryEndpoint(
            $this->metadata,
            $this->responseFactory,
            $this->streamFactory,
        );
    }

    public function getJwksEndpoint(string $keyId = 'default'): JwksEndpoint
    {
        return new JwksEndpoint(
            $this->publicKey,
            $this->responseFactory,
            $this->streamFactory,
            $keyId,
        );
    }

    public function getUserinfoEndpoint(): UserinfoEndpoint
    {
        return new UserinfoEndpoint(
            $this->claimsMapper,
            $this->scopeMapping,
            $this->responseFactory,
            $this->streamFactory,
        );
    }

    /**
     * @param array<string, mixed> $tokenResponse
     * @param string[] $scopes
     * @return array<string, mixed>
     */
    public function wrapTokenResponse(
        array $tokenResponse,
        string $identityId,
        string $clientId,
        array $scopes,
        ?string $nonce = null,
    ): array {
        if (!in_array('openid', $scopes, true)) {
            return $tokenResponse;
        }

        $accessToken = $tokenResponse['access_token'] ?? '';
        $atHash = is_string($accessToken) ? IdTokenBuilder::computeAtHash($accessToken) : null;

        $tokenResponse['id_token'] = $this->idTokenBuilder->build(
            $identityId,
            $clientId,
            $scopes,
            $nonce,
            $atHash,
        );

        return $tokenResponse;
    }
}
