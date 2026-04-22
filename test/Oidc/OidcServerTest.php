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

namespace Horde\OAuth\Test\Oidc;

use Horde\Http\ResponseFactory;
use Horde\Http\StreamFactory;
use Horde\Jwt\Key\PublicKey;
use Horde\Jwt\Signer\Rs256Signer;
use Horde\Jwt\TokenEncoder;
use Horde\OAuth\Oidc\ClaimsMapper;
use Horde\OAuth\Oidc\IdTokenBuilder;
use Horde\OAuth\Oidc\OidcServer;
use Horde\OAuth\Oidc\ScopeClaimsMapping;
use Horde\OAuth\Server\AuthorizationServer;
use Horde\OAuth\Server\Repository\InMemory\InMemoryAccessTokenRepository;
use Horde\OAuth\Server\Repository\InMemory\InMemoryAuthorizationCodeRepository;
use Horde\OAuth\Server\Repository\InMemory\InMemoryClientRepository;
use Horde\OAuth\Server\Repository\InMemory\InMemoryConsentRepository;
use Horde\OAuth\Server\Repository\InMemory\InMemoryRefreshTokenRepository;
use Horde\OAuth\Server\Repository\InMemory\InMemoryScopeRepository;
use Horde\OAuth\Server\ServerMetadata;
use Horde\OAuth\Test\RsaKeyHelper;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(OidcServer::class)]
final class OidcServerTest extends TestCase
{
    use RsaKeyHelper;

    private OidcServer $oidcServer;

    protected function setUp(): void
    {
        $rsaKey = self::generateRsaKey();
        $pubKey = PublicKey::fromPrivateKey($rsaKey);
        $signer = new Rs256Signer($rsaKey);
        $encoder = new TokenEncoder();
        $metadata = new ServerMetadata('https://example.com', '/authorize', '/token');

        $claimsMapper = new class implements ClaimsMapper {
            public function getClaims(string $identityId, array $claimNames): array
            {
                return ['name' => 'Test'];
            }
        };
        $scopeMapping = new ScopeClaimsMapping();
        $idTokenBuilder = new IdTokenBuilder($encoder, $signer, $claimsMapper, $scopeMapping, 'https://example.com');

        $authServer = new AuthorizationServer(
            new InMemoryClientRepository(),
            new InMemoryAccessTokenRepository(),
            new InMemoryRefreshTokenRepository(),
            new InMemoryAuthorizationCodeRepository(),
            new InMemoryScopeRepository(),
            new InMemoryConsentRepository(),
            $encoder,
            $signer,
            new ResponseFactory(),
            new StreamFactory(),
            $metadata,
        );

        $this->oidcServer = new OidcServer(
            $authServer,
            $idTokenBuilder,
            $claimsMapper,
            $scopeMapping,
            $pubKey,
            $metadata,
            new ResponseFactory(),
            new StreamFactory(),
        );
    }

    public function testWrapTokenResponseAddsIdToken(): void
    {
        $tokenResponse = ['access_token' => 'at1', 'token_type' => 'Bearer'];
        $result = $this->oidcServer->wrapTokenResponse($tokenResponse, 'user1', 'c1', ['openid'], 'nonce1');
        self::assertArrayHasKey('id_token', $result);
        $parts = explode('.', $result['id_token']);
        self::assertCount(3, $parts);
    }

    public function testWrapTokenResponseSkipsWithoutOpenidScope(): void
    {
        $tokenResponse = ['access_token' => 'at1', 'token_type' => 'Bearer'];
        $result = $this->oidcServer->wrapTokenResponse($tokenResponse, 'user1', 'c1', ['profile']);
        self::assertArrayNotHasKey('id_token', $result);
    }

    public function testGetDiscoveryEndpoint(): void
    {
        $endpoint = $this->oidcServer->getDiscoveryEndpoint();
        self::assertInstanceOf(\Psr\Http\Server\RequestHandlerInterface::class, $endpoint);
    }

    public function testGetJwksEndpoint(): void
    {
        $endpoint = $this->oidcServer->getJwksEndpoint('my-key');
        self::assertInstanceOf(\Psr\Http\Server\RequestHandlerInterface::class, $endpoint);
    }

    public function testGetUserinfoEndpoint(): void
    {
        $endpoint = $this->oidcServer->getUserinfoEndpoint();
        self::assertInstanceOf(\Psr\Http\Server\RequestHandlerInterface::class, $endpoint);
    }
}
