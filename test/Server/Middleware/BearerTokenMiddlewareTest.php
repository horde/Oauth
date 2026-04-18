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

namespace Horde\Oauth\Test\Server\Middleware;

use Horde\Http\ResponseFactory;
use Horde\Http\ServerRequest;
use Horde\Http\StreamFactory;
use Horde\Jwt\Key\PrivateKey;
use Horde\Jwt\Key\PublicKey;
use Horde\Jwt\Signer\Rs256Signer;
use Horde\Jwt\TokenDecoder;
use Horde\Jwt\TokenEncoder;
use Horde\Jwt\Verifier\Rs256Verifier;
use Horde\Oauth\Server\Entity\AccessToken;
use Horde\Oauth\Server\Middleware\BearerTokenMiddleware;
use Horde\Oauth\Server\Repository\InMemory\InMemoryAccessTokenRepository;
use Horde\Oauth\Test\RsaKeyHelper;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use DateTimeImmutable;

#[CoversClass(BearerTokenMiddleware::class)]
final class BearerTokenMiddlewareTest extends TestCase
{
    use RsaKeyHelper;

    private PrivateKey $rsaKey;
    private BearerTokenMiddleware $middleware;
    private InMemoryAccessTokenRepository $tokenRepo;

    protected function setUp(): void
    {
        $this->rsaKey = self::generateRsaKey();
        $this->tokenRepo = new InMemoryAccessTokenRepository();
        $verifier = new Rs256Verifier(PublicKey::fromPrivateKey($this->rsaKey));
        $this->middleware = new BearerTokenMiddleware(
            new TokenDecoder(),
            $verifier,
            $this->tokenRepo,
            new ResponseFactory(),
            new StreamFactory(),
        );
    }

    private function makeToken(string $jti = 'jti1', string $sub = 'user1', string $scope = 'openid'): string
    {
        $encoder = new TokenEncoder();
        $signer = new Rs256Signer($this->rsaKey);
        $token = $encoder->encode([
            'sub' => $sub,
            'jti' => $jti,
            'client_id' => 'c1',
            'scope' => $scope,
        ], $signer, 3600);
        return $token->toString();
    }

    private function nextHandler(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            public ?ServerRequestInterface $receivedRequest = null;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->receivedRequest = $request;
                return (new ResponseFactory())->createResponse(200);
            }
        };
    }

    public function testValidToken(): void
    {
        $jwt = $this->makeToken();
        $request = (new ServerRequest('GET', 'https://example.com/resource'))
            ->withHeader('Authorization', "Bearer {$jwt}");
        $next = $this->nextHandler();
        $response = $this->middleware->process($request, $next);

        self::assertSame(200, $response->getStatusCode());
        self::assertNotNull($next->receivedRequest);
        self::assertSame('user1', $next->receivedRequest->getAttribute('oauth_user_id'));
        self::assertSame('c1', $next->receivedRequest->getAttribute('oauth_client_id'));
        self::assertSame('openid', $next->receivedRequest->getAttribute('oauth_scopes'));
    }

    public function testRevokedTokenRejects(): void
    {
        $jwt = $this->makeToken('revoked-jti');
        $this->tokenRepo->persist(new AccessToken('revoked-jti', 'c1', 'user1', 'openid', new DateTimeImmutable('+1 hour')));
        $this->tokenRepo->revoke('revoked-jti');

        $request = (new ServerRequest('GET', 'https://example.com/resource'))
            ->withHeader('Authorization', "Bearer {$jwt}");
        $response = $this->middleware->process($request, $this->nextHandler());

        self::assertSame(401, $response->getStatusCode());
        self::assertStringContainsString('Bearer', $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testMissingTokenWhenRequired(): void
    {
        $request = new ServerRequest('GET', 'https://example.com/resource');
        $response = $this->middleware->process($request, $this->nextHandler());
        self::assertSame(401, $response->getStatusCode());
    }

    public function testMissingTokenWhenOptional(): void
    {
        $verifier = new Rs256Verifier(PublicKey::fromPrivateKey($this->rsaKey));
        $middleware = new BearerTokenMiddleware(
            new TokenDecoder(),
            $verifier,
            $this->tokenRepo,
            new ResponseFactory(),
            new StreamFactory(),
            required: false,
        );
        $request = new ServerRequest('GET', 'https://example.com/resource');
        $next = $this->nextHandler();
        $response = $middleware->process($request, $next);
        self::assertSame(200, $response->getStatusCode());
        self::assertNotNull($next->receivedRequest);
    }

    public function testInvalidJwtRejects(): void
    {
        $request = (new ServerRequest('GET', 'https://example.com/resource'))
            ->withHeader('Authorization', 'Bearer not.a.jwt');
        $response = $this->middleware->process($request, $this->nextHandler());
        self::assertSame(401, $response->getStatusCode());
    }
}
