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

namespace Horde\Oauth\Test\Server\ClientAuthentication;

use Horde\Http\ServerRequest;
use Horde\Oauth\Exception\InvalidClientException;
use Horde\Oauth\Server\ClientAuthentication\ClientAuthenticatorChain;
use Horde\Oauth\Server\ClientAuthentication\ClientSecretBasic;
use Horde\Oauth\Server\ClientAuthentication\ClientSecretPost;
use Horde\Oauth\Server\Entity\Client;
use Horde\Oauth\Server\Repository\InMemory\InMemoryClientRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ClientAuthenticatorChain::class)]
final class ClientAuthenticatorChainTest extends TestCase
{
    private InMemoryClientRepository $repo;
    private ClientAuthenticatorChain $chain;

    protected function setUp(): void
    {
        $this->repo = new InMemoryClientRepository(
            new Client(
                'conf-client',
                password_hash('secret', PASSWORD_BCRYPT),
                'Confidential',
                ['https://example.com/cb'],
                ['authorization_code'],
                'openid',
                'confidential',
                'client_secret_basic',
            ),
            new Client(
                'pub-client',
                null,
                'Public',
                ['https://example.com/cb'],
                ['authorization_code'],
                'openid',
                'public',
                'client_secret_post',
            ),
        );
        $this->chain = new ClientAuthenticatorChain(
            $this->repo,
            new ClientSecretBasic(),
            new ClientSecretPost(),
        );
    }

    public function testAuthenticateConfidentialClient(): void
    {
        $encoded = base64_encode('conf-client:secret');
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withHeader('Authorization', "Basic {$encoded}");
        $client = $this->chain->authenticateClient($request);
        self::assertSame('conf-client', $client->clientId);
    }

    public function testAuthenticateClientWrongSecretThrows(): void
    {
        $encoded = base64_encode('conf-client:wrong');
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withHeader('Authorization', "Basic {$encoded}");
        $this->expectException(InvalidClientException::class);
        $this->chain->authenticateClient($request);
    }

    public function testAuthenticateClientUnknownThrows(): void
    {
        $encoded = base64_encode('unknown:secret');
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withHeader('Authorization', "Basic {$encoded}");
        $this->expectException(InvalidClientException::class);
        $this->chain->authenticateClient($request);
    }

    public function testAuthenticateClientNoCredentialsThrows(): void
    {
        $request = new ServerRequest('POST', 'https://example.com/token');
        $this->expectException(InvalidClientException::class);
        $this->chain->authenticateClient($request);
    }

    public function testAuthenticateClientOrPublicConfidential(): void
    {
        $encoded = base64_encode('conf-client:secret');
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withHeader('Authorization', "Basic {$encoded}");
        $client = $this->chain->authenticateClientOrPublic($request);
        self::assertSame('conf-client', $client->clientId);
    }

    public function testAuthenticateClientOrPublicFallback(): void
    {
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody(['client_id' => 'pub-client']);
        $client = $this->chain->authenticateClientOrPublic($request);
        self::assertSame('pub-client', $client->clientId);
    }

    public function testAuthenticateClientOrPublicConfidentialMustAuth(): void
    {
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody(['client_id' => 'conf-client']);
        $this->expectException(InvalidClientException::class);
        $this->chain->authenticateClientOrPublic($request);
    }

    public function testAuthenticateClientOrPublicNoIdThrows(): void
    {
        $request = new ServerRequest('POST', 'https://example.com/token');
        $this->expectException(InvalidClientException::class);
        $this->chain->authenticateClientOrPublic($request);
    }

    public function testAuthMethodMismatchThrows(): void
    {
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody(['client_id' => 'conf-client', 'client_secret' => 'secret']);
        $this->expectException(InvalidClientException::class);
        $this->expectExceptionMessage('Invalid authentication method');
        $this->chain->authenticateClient($request);
    }
}
