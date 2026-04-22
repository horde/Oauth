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
use Horde\OAuth\Client\PkceGenerator;
use Horde\OAuth\Exception\InvalidGrantException;
use Horde\OAuth\Exception\InvalidRequestException;
use Horde\OAuth\Server\Entity\AuthorizationCode;
use Horde\OAuth\Server\Entity\Client;
use Horde\OAuth\Server\Entity\Scope;
use Horde\OAuth\Server\Grant\AuthorizationCodeGrant;
use Horde\OAuth\Server\Repository\InMemory\InMemoryAccessTokenRepository;
use Horde\OAuth\Server\Repository\InMemory\InMemoryAuthorizationCodeRepository;
use Horde\OAuth\Server\Repository\InMemory\InMemoryRefreshTokenRepository;
use Horde\OAuth\Server\Repository\InMemory\InMemoryScopeRepository;
use Horde\OAuth\Server\Token\AccessTokenIssuer;
use Horde\OAuth\Server\Token\RefreshTokenIssuer;
use Horde\OAuth\Test\RsaKeyHelper;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use DateTimeImmutable;

#[CoversClass(AuthorizationCodeGrant::class)]
final class AuthorizationCodeGrantTest extends TestCase
{
    use RsaKeyHelper;

    private InMemoryAuthorizationCodeRepository $codeRepo;
    private AuthorizationCodeGrant $grant;
    private Client $client;

    protected function setUp(): void
    {
        $rsaKey = self::generateRsaKey();
        $atRepo = new InMemoryAccessTokenRepository();
        $rtRepo = new InMemoryRefreshTokenRepository();
        $this->codeRepo = new InMemoryAuthorizationCodeRepository();

        $tokenIssuer = new AccessTokenIssuer(
            new TokenEncoder(),
            new Rs256Signer($rsaKey),
            $atRepo,
            'https://example.com',
        );
        $rtIssuer = new RefreshTokenIssuer($rtRepo);
        $scopeRepo = new InMemoryScopeRepository(new Scope('openid'), new Scope('profile'));

        $this->grant = new AuthorizationCodeGrant(
            $this->codeRepo,
            $tokenIssuer,
            $rtIssuer,
            $scopeRepo,
        );
        $this->client = new Client(
            'c1',
            password_hash('s', PASSWORD_BCRYPT),
            'Test',
            ['https://example.com/cb'],
            ['authorization_code'],
            'openid',
            'confidential',
        );
    }

    public function testGetIdentifier(): void
    {
        self::assertSame('authorization_code', $this->grant->getIdentifier());
    }

    public function testSuccessfulExchange(): void
    {
        $this->codeRepo->persist(new AuthorizationCode(
            'valid-code',
            'c1',
            'user1',
            'https://example.com/cb',
            'openid',
            null,
            null,
            'nonce123',
            new DateTimeImmutable('+10 minutes'),
        ));

        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody([
                'grant_type' => 'authorization_code',
                'code' => 'valid-code',
                'redirect_uri' => 'https://example.com/cb',
            ]);

        $result = $this->grant->respondToTokenRequest($request, $this->client);
        self::assertArrayHasKey('access_token', $result);
        self::assertArrayHasKey('refresh_token', $result);
        self::assertSame('user1', $result['_identity_id']);
        self::assertSame('nonce123', $result['_nonce']);
        self::assertTrue($this->codeRepo->isUsed('valid-code'));
    }

    public function testSuccessfulExchangeWithPkce(): void
    {
        $verifier = PkceGenerator::generateVerifier();
        $challenge = PkceGenerator::computeChallenge($verifier);

        $this->codeRepo->persist(new AuthorizationCode(
            'pkce-code',
            'c1',
            'user1',
            'https://example.com/cb',
            'openid',
            $challenge,
            'S256',
            null,
            new DateTimeImmutable('+10 minutes'),
        ));

        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody([
                'grant_type' => 'authorization_code',
                'code' => 'pkce-code',
                'redirect_uri' => 'https://example.com/cb',
                'code_verifier' => $verifier,
            ]);

        $result = $this->grant->respondToTokenRequest($request, $this->client);
        self::assertArrayHasKey('access_token', $result);
    }

    public function testPkceFailsWithWrongVerifier(): void
    {
        $challenge = PkceGenerator::computeChallenge('real-verifier');
        $this->codeRepo->persist(new AuthorizationCode(
            'pkce-code',
            'c1',
            'user1',
            'https://example.com/cb',
            'openid',
            $challenge,
            'S256',
            null,
            new DateTimeImmutable('+10 minutes'),
        ));

        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody([
                'grant_type' => 'authorization_code',
                'code' => 'pkce-code',
                'redirect_uri' => 'https://example.com/cb',
                'code_verifier' => 'wrong-verifier',
            ]);

        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessage('PKCE');
        $this->grant->respondToTokenRequest($request, $this->client);
    }

    public function testMissingCodeThrows(): void
    {
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody(['grant_type' => 'authorization_code']);
        $this->expectException(InvalidRequestException::class);
        $this->grant->respondToTokenRequest($request, $this->client);
    }

    public function testInvalidCodeThrows(): void
    {
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody(['grant_type' => 'authorization_code', 'code' => 'nonexistent']);
        $this->expectException(InvalidGrantException::class);
        $this->grant->respondToTokenRequest($request, $this->client);
    }

    public function testExpiredCodeThrows(): void
    {
        $this->codeRepo->persist(new AuthorizationCode(
            'expired',
            'c1',
            'user1',
            'https://example.com/cb',
            'openid',
            null,
            null,
            null,
            new DateTimeImmutable('-1 second'),
        ));
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody(['grant_type' => 'authorization_code', 'code' => 'expired', 'redirect_uri' => 'https://example.com/cb']);
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessage('expired');
        $this->grant->respondToTokenRequest($request, $this->client);
    }

    public function testUsedCodeThrows(): void
    {
        $this->codeRepo->persist(new AuthorizationCode(
            'used',
            'c1',
            'user1',
            'https://example.com/cb',
            'openid',
            null,
            null,
            null,
            new DateTimeImmutable('+10 minutes'),
            used: true,
        ));
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody(['grant_type' => 'authorization_code', 'code' => 'used', 'redirect_uri' => 'https://example.com/cb']);
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessage('already been used');
        $this->grant->respondToTokenRequest($request, $this->client);
    }

    public function testClientMismatchThrows(): void
    {
        $this->codeRepo->persist(new AuthorizationCode(
            'code',
            'other-client',
            'user1',
            'https://example.com/cb',
            'openid',
            null,
            null,
            null,
            new DateTimeImmutable('+10 minutes'),
        ));
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody(['grant_type' => 'authorization_code', 'code' => 'code', 'redirect_uri' => 'https://example.com/cb']);
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessage('not issued to this client');
        $this->grant->respondToTokenRequest($request, $this->client);
    }

    public function testRedirectUriMismatchThrows(): void
    {
        $this->codeRepo->persist(new AuthorizationCode(
            'code',
            'c1',
            'user1',
            'https://example.com/cb',
            'openid',
            null,
            null,
            null,
            new DateTimeImmutable('+10 minutes'),
        ));
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody(['grant_type' => 'authorization_code', 'code' => 'code', 'redirect_uri' => 'https://evil.com/cb']);
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessage('Redirect URI');
        $this->grant->respondToTokenRequest($request, $this->client);
    }

    public function testPkceMissingVerifierThrows(): void
    {
        $this->codeRepo->persist(new AuthorizationCode(
            'pkce',
            'c1',
            'user1',
            'https://example.com/cb',
            'openid',
            'challenge',
            'S256',
            null,
            new DateTimeImmutable('+10 minutes'),
        ));
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody(['grant_type' => 'authorization_code', 'code' => 'pkce', 'redirect_uri' => 'https://example.com/cb']);
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('code_verifier');
        $this->grant->respondToTokenRequest($request, $this->client);
    }
}
