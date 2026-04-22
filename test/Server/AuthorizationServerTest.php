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

namespace Horde\OAuth\Test\Server;

use Horde\Http\ResponseFactory;
use Horde\Http\StreamFactory;
use Horde\Jwt\Key\PublicKey;
use Horde\Jwt\Signer\Rs256Signer;
use Horde\Jwt\TokenEncoder;
use Horde\Jwt\Verifier\Rs256Verifier;
use Horde\OAuth\Server\AuthorizationServer;
use Horde\OAuth\Server\Entity\Scope;
use Horde\OAuth\Server\Grant\AuthorizationCodeGrant;
use Horde\OAuth\Server\Grant\ClientCredentialsGrant;
use Horde\OAuth\Server\Grant\RefreshTokenGrant;
use Horde\OAuth\Server\Handler\AuthorizationEndpoint;
use Horde\OAuth\Server\Handler\IntrospectionEndpoint;
use Horde\OAuth\Server\Handler\MetadataEndpoint;
use Horde\OAuth\Server\Handler\RevocationEndpoint;
use Horde\OAuth\Server\Handler\TokenEndpoint;
use Horde\OAuth\Server\Middleware\BearerTokenMiddleware;
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

#[CoversClass(AuthorizationServer::class)]
final class AuthorizationServerTest extends TestCase
{
    use RsaKeyHelper;

    private AuthorizationServer $server;
    private \Horde\Jwt\Key\PrivateKey $rsaKey;

    protected function setUp(): void
    {
        $this->rsaKey = self::generateRsaKey();
        $metadata = new ServerMetadata('https://example.com', '/authorize', '/token');
        $this->server = new AuthorizationServer(
            new InMemoryClientRepository(),
            new InMemoryAccessTokenRepository(),
            new InMemoryRefreshTokenRepository(),
            new InMemoryAuthorizationCodeRepository(),
            new InMemoryScopeRepository(new Scope('openid')),
            new InMemoryConsentRepository(),
            new TokenEncoder(),
            new Rs256Signer($this->rsaKey),
            new ResponseFactory(),
            new StreamFactory(),
            $metadata,
        );
    }

    public function testCreateGrants(): void
    {
        $authCodeGrant = $this->server->createAuthorizationCodeGrant();
        self::assertInstanceOf(AuthorizationCodeGrant::class, $authCodeGrant);

        $ccGrant = $this->server->createClientCredentialsGrant();
        self::assertInstanceOf(ClientCredentialsGrant::class, $ccGrant);

        $rtGrant = $this->server->createRefreshTokenGrant();
        self::assertInstanceOf(RefreshTokenGrant::class, $rtGrant);
    }

    public function testGetEndpoints(): void
    {
        $this->server->enableGrant($this->server->createClientCredentialsGrant());
        self::assertInstanceOf(TokenEndpoint::class, $this->server->getTokenEndpoint());
        self::assertInstanceOf(AuthorizationEndpoint::class, $this->server->getAuthorizationEndpoint());
        self::assertInstanceOf(RevocationEndpoint::class, $this->server->getRevocationEndpoint());
        self::assertInstanceOf(IntrospectionEndpoint::class, $this->server->getIntrospectionEndpoint());
        self::assertInstanceOf(MetadataEndpoint::class, $this->server->getMetadataEndpoint());
    }

    public function testGetBearerMiddleware(): void
    {
        $verifier = new Rs256Verifier(PublicKey::fromPrivateKey($this->rsaKey));
        $mw = $this->server->getBearerMiddleware($verifier);
        self::assertInstanceOf(BearerTokenMiddleware::class, $mw);
    }

    public function testEnableGrant(): void
    {
        $grant = $this->server->createClientCredentialsGrant();
        $this->server->enableGrant($grant);
        $endpoint = $this->server->getTokenEndpoint();
        self::assertInstanceOf(TokenEndpoint::class, $endpoint);
    }
}
