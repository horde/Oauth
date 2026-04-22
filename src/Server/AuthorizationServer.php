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

use Horde\Jwt\Signer\SignerInterface;
use Horde\Jwt\TokenDecoder;
use Horde\Jwt\TokenEncoder;
use Horde\Jwt\Verifier\VerifierInterface;
use Horde\OAuth\Server\ClientAuthentication\ClientAuthenticatorChain;
use Horde\OAuth\Server\ClientAuthentication\ClientSecretBasic;
use Horde\OAuth\Server\ClientAuthentication\ClientSecretPost;
use Horde\OAuth\Server\Grant\AuthorizationCodeGrant;
use Horde\OAuth\Server\Grant\ClientCredentialsGrant;
use Horde\OAuth\Server\Grant\Grant;
use Horde\OAuth\Server\Grant\RefreshTokenGrant;
use Horde\OAuth\Server\Handler\AuthorizationEndpoint;
use Horde\OAuth\Server\Handler\IntrospectionEndpoint;
use Horde\OAuth\Server\Handler\MetadataEndpoint;
use Horde\OAuth\Server\Handler\RevocationEndpoint;
use Horde\OAuth\Server\Handler\TokenEndpoint;
use Horde\OAuth\Server\Middleware\BearerTokenMiddleware;
use Horde\OAuth\Server\Repository\AccessTokenRepository;
use Horde\OAuth\Server\Repository\AuthorizationCodeRepository;
use Horde\OAuth\Server\Repository\ClientRepository;
use Horde\OAuth\Server\Repository\ConsentRepository;
use Horde\OAuth\Server\Repository\RefreshTokenRepository;
use Horde\OAuth\Server\Repository\ScopeRepository;
use Horde\OAuth\Server\Token\AccessTokenIssuer;
use Horde\OAuth\Server\Token\RefreshTokenIssuer;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

final class AuthorizationServer
{
    /** @var array<string, Grant> */
    private array $grants = [];

    public function __construct(
        private readonly ClientRepository $clientRepository,
        private readonly AccessTokenRepository $accessTokenRepository,
        private readonly RefreshTokenRepository $refreshTokenRepository,
        private readonly AuthorizationCodeRepository $authCodeRepository,
        private readonly ScopeRepository $scopeRepository,
        private readonly ConsentRepository $consentRepository,
        private readonly TokenEncoder $tokenEncoder,
        private readonly SignerInterface $signer,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly StreamFactoryInterface $streamFactory,
        private readonly ServerMetadata $metadata,
    ) {}

    public function enableGrant(Grant $grant): void
    {
        $this->grants[$grant->getIdentifier()] = $grant;
    }

    public function getTokenEndpoint(): TokenEndpoint
    {
        return new TokenEndpoint(
            $this->buildClientAuthenticator(),
            $this->responseFactory,
            $this->streamFactory,
            ...array_values($this->grants),
        );
    }

    public function getAuthorizationEndpoint(): AuthorizationEndpoint
    {
        return new AuthorizationEndpoint(
            $this->clientRepository,
            $this->scopeRepository,
            $this->authCodeRepository,
            $this->responseFactory,
            $this->streamFactory,
        );
    }

    public function getRevocationEndpoint(): RevocationEndpoint
    {
        return new RevocationEndpoint(
            $this->buildClientAuthenticator(),
            $this->accessTokenRepository,
            $this->refreshTokenRepository,
            $this->responseFactory,
            $this->streamFactory,
        );
    }

    public function getIntrospectionEndpoint(): IntrospectionEndpoint
    {
        return new IntrospectionEndpoint(
            $this->buildClientAuthenticator(),
            $this->accessTokenRepository,
            $this->refreshTokenRepository,
            $this->responseFactory,
            $this->streamFactory,
        );
    }

    public function getMetadataEndpoint(): MetadataEndpoint
    {
        return new MetadataEndpoint(
            $this->metadata,
            $this->responseFactory,
            $this->streamFactory,
        );
    }

    /**
     * @param array<string, mixed> $options
     */
    public function getBearerMiddleware(VerifierInterface $verifier, array $options = []): BearerTokenMiddleware
    {
        return new BearerTokenMiddleware(
            new TokenDecoder(),
            $verifier,
            $this->accessTokenRepository,
            $this->responseFactory,
            $this->streamFactory,
            required: (bool) ($options['required'] ?? true),
            verifyOptions: $options['verify'] ?? [],
        );
    }

    public function createAccessTokenIssuer(int $ttl = 3600): AccessTokenIssuer
    {
        return new AccessTokenIssuer(
            $this->tokenEncoder,
            $this->signer,
            $this->accessTokenRepository,
            $this->metadata->issuer,
            $ttl,
        );
    }

    public function createRefreshTokenIssuer(int $ttl = 2592000): RefreshTokenIssuer
    {
        return new RefreshTokenIssuer(
            $this->refreshTokenRepository,
            $ttl,
        );
    }

    public function createAuthorizationCodeGrant(bool $issueRefreshTokens = true): AuthorizationCodeGrant
    {
        return new AuthorizationCodeGrant(
            $this->authCodeRepository,
            $this->createAccessTokenIssuer(),
            $issueRefreshTokens ? $this->createRefreshTokenIssuer() : null,
            $this->scopeRepository,
        );
    }

    public function createClientCredentialsGrant(): ClientCredentialsGrant
    {
        return new ClientCredentialsGrant(
            $this->createAccessTokenIssuer(),
            $this->scopeRepository,
        );
    }

    public function createRefreshTokenGrant(bool $issueRefreshTokens = true): RefreshTokenGrant
    {
        return new RefreshTokenGrant(
            $this->refreshTokenRepository,
            $this->accessTokenRepository,
            $this->createAccessTokenIssuer(),
            $issueRefreshTokens ? $this->createRefreshTokenIssuer() : null,
            $this->scopeRepository,
        );
    }

    private function buildClientAuthenticator(): ClientAuthenticatorChain
    {
        return new ClientAuthenticatorChain(
            $this->clientRepository,
            new ClientSecretBasic(),
            new ClientSecretPost(),
        );
    }
}
