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

namespace Horde\Oauth\Test\Server\Entity;

use Horde\Oauth\Server\Entity\Client;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Client::class)]
final class ClientTest extends TestCase
{
    private function createClient(string $type = 'confidential', ?string $secretHash = null): Client
    {
        return new Client(
            clientId: 'test-client',
            clientSecretHash: $secretHash ?? password_hash('secret123', PASSWORD_BCRYPT),
            clientName: 'Test App',
            redirectUris: ['https://example.com/callback'],
            grantTypes: ['authorization_code', 'refresh_token'],
            scope: 'openid profile',
            clientType: $type,
        );
    }

    public function testConfidentialClient(): void
    {
        $client = $this->createClient();
        self::assertTrue($client->isConfidential());
        self::assertFalse($client->isPublic());
    }

    public function testPublicClient(): void
    {
        $client = $this->createClient('public', null);
        self::assertTrue($client->isPublic());
        self::assertFalse($client->isConfidential());
    }

    public function testVerifySecretCorrect(): void
    {
        $client = $this->createClient();
        self::assertTrue($client->verifySecret('secret123'));
    }

    public function testVerifySecretWrong(): void
    {
        $client = $this->createClient();
        self::assertFalse($client->verifySecret('wrong'));
    }

    public function testVerifySecretNullHash(): void
    {
        $client = $this->createClient('public', null);
        self::assertFalse($client->verifySecret('anything'));
    }

    public function testSupportsGrantType(): void
    {
        $client = $this->createClient();
        self::assertTrue($client->supportsGrantType('authorization_code'));
        self::assertTrue($client->supportsGrantType('refresh_token'));
        self::assertFalse($client->supportsGrantType('client_credentials'));
    }

    public function testHasRedirectUri(): void
    {
        $client = $this->createClient();
        self::assertTrue($client->hasRedirectUri('https://example.com/callback'));
        self::assertFalse($client->hasRedirectUri('https://evil.com/callback'));
    }

    public function testGetDefaultScopes(): void
    {
        $client = $this->createClient();
        $scopes = $client->getDefaultScopes();
        self::assertCount(2, $scopes);
        self::assertSame('openid', $scopes[0]->identifier);
        self::assertSame('profile', $scopes[1]->identifier);
    }
}
