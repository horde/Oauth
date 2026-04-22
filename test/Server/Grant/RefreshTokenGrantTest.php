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

namespace Horde\OAuth\Test\Server\Grant;

use Horde\Http\ServerRequest;
use Horde\Jwt\Signer\Rs256Signer;
use Horde\Jwt\TokenEncoder;
use Horde\OAuth\Exception\InvalidGrantException;
use Horde\OAuth\Exception\InvalidRequestException;
use Horde\OAuth\Server\Entity\Client;
use Horde\OAuth\Server\Entity\RefreshToken;
use Horde\OAuth\Server\Entity\Scope;
use Horde\OAuth\Server\Grant\RefreshTokenGrant;
use Horde\OAuth\Server\Repository\InMemory\InMemoryAccessTokenRepository;
use Horde\OAuth\Server\Repository\InMemory\InMemoryRefreshTokenRepository;
use Horde\OAuth\Server\Repository\InMemory\InMemoryScopeRepository;
use Horde\OAuth\Server\Token\AccessTokenIssuer;
use Horde\OAuth\Server\Token\RefreshTokenIssuer;
use Horde\OAuth\Test\RsaKeyHelper;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use DateTimeImmutable;

#[CoversClass(RefreshTokenGrant::class)]
final class RefreshTokenGrantTest extends TestCase
{
    use RsaKeyHelper;

    private InMemoryAccessTokenRepository $atRepo;
    private InMemoryRefreshTokenRepository $rtRepo;
    private RefreshTokenGrant $grant;
    private Client $client;

    protected function setUp(): void
    {
        $rsaKey = self::generateRsaKey();
        $this->atRepo = new InMemoryAccessTokenRepository();
        $this->rtRepo = new InMemoryRefreshTokenRepository();
        $scopeRepo = new InMemoryScopeRepository(new Scope('openid'), new Scope('profile'));

        $tokenIssuer = new AccessTokenIssuer(
            new TokenEncoder(),
            new Rs256Signer($rsaKey),
            $this->atRepo,
            'https://example.com',
        );
        $rtIssuer = new RefreshTokenIssuer($this->rtRepo);

        $this->grant = new RefreshTokenGrant(
            $this->rtRepo,
            $this->atRepo,
            $tokenIssuer,
            $rtIssuer,
            $scopeRepo,
        );
        $this->client = new Client(
            'c1',
            password_hash('s', PASSWORD_BCRYPT),
            'Test',
            ['https://example.com/cb'],
            ['refresh_token'],
            'openid',
            'confidential',
        );
    }

    public function testGetIdentifier(): void
    {
        self::assertSame('refresh_token', $this->grant->getIdentifier());
    }

    public function testSuccessfulRefresh(): void
    {
        $this->rtRepo->persist(new RefreshToken(
            'rt1',
            'at1',
            'c1',
            'user1',
            'openid profile',
            new DateTimeImmutable('+30 days'),
        ));
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody(['grant_type' => 'refresh_token', 'refresh_token' => 'rt1']);
        $result = $this->grant->respondToTokenRequest($request, $this->client);

        self::assertArrayHasKey('access_token', $result);
        self::assertArrayHasKey('refresh_token', $result);
        self::assertTrue($this->rtRepo->isRevoked('rt1'));
    }

    public function testScopeNarrowing(): void
    {
        $this->rtRepo->persist(new RefreshToken(
            'rt1',
            'at1',
            'c1',
            'user1',
            'openid profile',
            new DateTimeImmutable('+30 days'),
        ));
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody(['grant_type' => 'refresh_token', 'refresh_token' => 'rt1', 'scope' => 'openid']);
        $result = $this->grant->respondToTokenRequest($request, $this->client);
        self::assertSame('openid', $result['scope']);
    }

    public function testScopeEscalationThrows(): void
    {
        $this->rtRepo->persist(new RefreshToken(
            'rt1',
            'at1',
            'c1',
            'user1',
            'openid',
            new DateTimeImmutable('+30 days'),
        ));
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody(['grant_type' => 'refresh_token', 'refresh_token' => 'rt1', 'scope' => 'openid profile']);
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessage('exceeds');
        $this->grant->respondToTokenRequest($request, $this->client);
    }

    public function testMissingRefreshTokenThrows(): void
    {
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody(['grant_type' => 'refresh_token']);
        $this->expectException(InvalidRequestException::class);
        $this->grant->respondToTokenRequest($request, $this->client);
    }

    public function testRevokedRefreshTokenThrows(): void
    {
        $this->rtRepo->persist(new RefreshToken(
            'rt1',
            'at1',
            'c1',
            'user1',
            'openid',
            new DateTimeImmutable('+30 days'),
            revoked: true,
        ));
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody(['grant_type' => 'refresh_token', 'refresh_token' => 'rt1']);
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessage('revoked');
        $this->grant->respondToTokenRequest($request, $this->client);
    }

    public function testExpiredRefreshTokenThrows(): void
    {
        $this->rtRepo->persist(new RefreshToken(
            'rt1',
            'at1',
            'c1',
            'user1',
            'openid',
            new DateTimeImmutable('-1 second'),
        ));
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody(['grant_type' => 'refresh_token', 'refresh_token' => 'rt1']);
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessage('expired');
        $this->grant->respondToTokenRequest($request, $this->client);
    }

    public function testClientMismatchThrows(): void
    {
        $this->rtRepo->persist(new RefreshToken(
            'rt1',
            'at1',
            'other-client',
            'user1',
            'openid',
            new DateTimeImmutable('+30 days'),
        ));
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody(['grant_type' => 'refresh_token', 'refresh_token' => 'rt1']);
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessage('not issued to this client');
        $this->grant->respondToTokenRequest($request, $this->client);
    }
}
