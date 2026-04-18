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

namespace Horde\Oauth\Test\Server\Grant;

use Horde\Http\ServerRequest;
use Horde\Jwt\Signer\Rs256Signer;
use Horde\Jwt\TokenEncoder;
use Horde\Oauth\Server\Entity\Client;
use Horde\Oauth\Server\Entity\Scope;
use Horde\Oauth\Server\Grant\ClientCredentialsGrant;
use Horde\Oauth\Server\Repository\InMemory\InMemoryAccessTokenRepository;
use Horde\Oauth\Server\Repository\InMemory\InMemoryScopeRepository;
use Horde\Oauth\Server\Token\AccessTokenIssuer;
use Horde\Oauth\Test\RsaKeyHelper;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ClientCredentialsGrant::class)]
final class ClientCredentialsGrantTest extends TestCase
{
    use RsaKeyHelper;

    private ClientCredentialsGrant $grant;

    protected function setUp(): void
    {
        $rsaKey = self::generateRsaKey();
        $tokenIssuer = new AccessTokenIssuer(
            new TokenEncoder(),
            new Rs256Signer($rsaKey),
            new InMemoryAccessTokenRepository(),
            'https://example.com',
        );
        $scopeRepo = new InMemoryScopeRepository(new Scope('api'), new Scope('read'));
        $this->grant = new ClientCredentialsGrant($tokenIssuer, $scopeRepo);
    }

    public function testGetIdentifier(): void
    {
        self::assertSame('client_credentials', $this->grant->getIdentifier());
    }

    public function testRespondWithScope(): void
    {
        $client = new Client('c1', null, 'Test', [], ['client_credentials'], 'api', 'confidential');
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody(['grant_type' => 'client_credentials', 'scope' => 'api read']);
        $result = $this->grant->respondToTokenRequest($request, $client);

        self::assertArrayHasKey('access_token', $result);
        self::assertSame('Bearer', $result['token_type']);
        self::assertSame('api read', $result['scope']);
        self::assertArrayNotHasKey('_jti', $result);
    }

    public function testRespondDefaultScope(): void
    {
        $client = new Client('c1', null, 'Test', [], ['client_credentials'], 'api', 'confidential');
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody(['grant_type' => 'client_credentials']);
        $result = $this->grant->respondToTokenRequest($request, $client);
        self::assertSame('api', $result['scope']);
    }
}
