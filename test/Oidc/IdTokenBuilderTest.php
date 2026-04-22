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

use Horde\Jwt\Base64Url;
use Horde\Jwt\Key\PublicKey;
use Horde\Jwt\Signer\Rs256Signer;
use Horde\Jwt\TokenDecoder;
use Horde\Jwt\TokenEncoder;
use Horde\Jwt\Verifier\Rs256Verifier;
use Horde\OAuth\Oidc\ClaimsMapper;
use Horde\OAuth\Oidc\IdTokenBuilder;
use Horde\OAuth\Oidc\ScopeClaimsMapping;
use Horde\OAuth\Test\RsaKeyHelper;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(IdTokenBuilder::class)]
final class IdTokenBuilderTest extends TestCase
{
    use RsaKeyHelper;

    private \Horde\Jwt\Key\PrivateKey $rsaKey;
    private IdTokenBuilder $builder;

    protected function setUp(): void
    {
        $this->rsaKey = self::generateRsaKey();
        $claimsMapper = new class implements ClaimsMapper {
            public function getClaims(string $identityId, array $claimNames): array
            {
                $all = [
                    'name' => 'Test User',
                    'email' => 'test@example.com',
                    'email_verified' => true,
                ];
                return array_intersect_key($all, array_flip($claimNames));
            }
        };
        $this->builder = new IdTokenBuilder(
            new TokenEncoder(),
            new Rs256Signer($this->rsaKey),
            $claimsMapper,
            new ScopeClaimsMapping(),
            'https://example.com',
            3600,
        );
    }

    public function testBuildProducesValidJwt(): void
    {
        $jwt = $this->builder->build('user1', 'c1', ['openid', 'profile'], 'nonce123');
        $parts = explode('.', $jwt);
        self::assertCount(3, $parts);
    }

    public function testBuildContainsStandardClaims(): void
    {
        $jwt = $this->builder->build('user1', 'c1', ['openid'], 'nonce123');
        $decoder = new TokenDecoder();
        $verifier = new Rs256Verifier(PublicKey::fromPrivateKey($this->rsaKey));
        $token = $decoder->decode($jwt, $verifier, ['verify_exp' => true]);

        self::assertSame('https://example.com', $token->getClaim('iss'));
        self::assertSame('user1', $token->getSubject());
        self::assertSame('c1', $token->getClaim('aud'));
        self::assertSame('nonce123', $token->getClaim('nonce'));
        self::assertNotNull($token->getClaim('auth_time'));
    }

    public function testBuildIncludesUserClaims(): void
    {
        $jwt = $this->builder->build('user1', 'c1', ['openid', 'email']);
        $decoder = new TokenDecoder();
        $verifier = new Rs256Verifier(PublicKey::fromPrivateKey($this->rsaKey));
        $token = $decoder->decode($jwt, $verifier);
        self::assertSame('test@example.com', $token->getClaim('email'));
    }

    public function testBuildWithAtHash(): void
    {
        $jwt = $this->builder->build('user1', 'c1', ['openid'], null, 'some-at-hash');
        $decoder = new TokenDecoder();
        $verifier = new Rs256Verifier(PublicKey::fromPrivateKey($this->rsaKey));
        $token = $decoder->decode($jwt, $verifier);
        self::assertSame('some-at-hash', $token->getClaim('at_hash'));
    }

    public function testBuildWithCodeHash(): void
    {
        $jwt = $this->builder->build('user1', 'c1', ['openid'], null, null, 'some-c-hash');
        $decoder = new TokenDecoder();
        $verifier = new Rs256Verifier(PublicKey::fromPrivateKey($this->rsaKey));
        $token = $decoder->decode($jwt, $verifier);
        self::assertSame('some-c-hash', $token->getClaim('c_hash'));
    }

    public function testComputeAtHash(): void
    {
        $hash = IdTokenBuilder::computeAtHash('access-token-value');
        self::assertNotEmpty($hash);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $hash);

        $fullHash = hash('sha256', 'access-token-value', true);
        $expected = Base64Url::encode(substr($fullHash, 0, (int) (strlen($fullHash) / 2)));
        self::assertSame($expected, $hash);
    }

    public function testNonceOmittedWhenNull(): void
    {
        $jwt = $this->builder->build('user1', 'c1', ['openid']);
        $decoder = new TokenDecoder();
        $verifier = new Rs256Verifier(PublicKey::fromPrivateKey($this->rsaKey));
        $token = $decoder->decode($jwt, $verifier);
        self::assertNull($token->getClaim('nonce'));
    }
}
