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

namespace Horde\OAuth\Test\Exception;

use Horde\OAuth\Exception\AccessDeniedException;
use Horde\OAuth\Exception\InvalidClientException;
use Horde\OAuth\Exception\InvalidGrantException;
use Horde\OAuth\Exception\InvalidRequestException;
use Horde\OAuth\Exception\InvalidScopeException;
use Horde\OAuth\Exception\OAuthException;
use Horde\OAuth\Exception\UnauthorizedClientException;
use Horde\OAuth\Exception\UnsupportedGrantTypeException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;

#[CoversClass(OAuthException::class)]
#[CoversClass(AccessDeniedException::class)]
#[CoversClass(InvalidClientException::class)]
#[CoversClass(InvalidGrantException::class)]
#[CoversClass(InvalidRequestException::class)]
#[CoversClass(InvalidScopeException::class)]
#[CoversClass(UnauthorizedClientException::class)]
#[CoversClass(UnsupportedGrantTypeException::class)]
final class OAuthExceptionTest extends TestCase
{
    public function testBaseExceptionCarriesErrorCode(): void
    {
        $e = new OAuthException('server_error', 'Something broke', 'https://example.com/err', 500);
        self::assertSame('server_error', $e->getError());
        self::assertSame('Something broke', $e->getErrorDescription());
        self::assertSame('https://example.com/err', $e->getErrorUri());
        self::assertSame(500, $e->getHttpStatusCode());
    }

    public function testBaseExceptionDefaults(): void
    {
        $e = new OAuthException('test_error');
        self::assertSame('', $e->getErrorDescription());
        self::assertSame('', $e->getErrorUri());
        self::assertSame(400, $e->getHttpStatusCode());
    }

    public function testInvalidClientIs401(): void
    {
        $e = new InvalidClientException('bad client');
        self::assertSame('invalid_client', $e->getError());
        self::assertSame(401, $e->getHttpStatusCode());
    }

    public function testInvalidGrantIs400(): void
    {
        $e = new InvalidGrantException('bad grant');
        self::assertSame('invalid_grant', $e->getError());
        self::assertSame(400, $e->getHttpStatusCode());
    }

    public function testInvalidRequestIs400(): void
    {
        $e = new InvalidRequestException('bad request');
        self::assertSame('invalid_request', $e->getError());
        self::assertSame(400, $e->getHttpStatusCode());
    }

    public function testInvalidScopeIs400(): void
    {
        $e = new InvalidScopeException('bad scope');
        self::assertSame('invalid_scope', $e->getError());
        self::assertSame(400, $e->getHttpStatusCode());
    }

    public function testUnauthorizedClientIs400(): void
    {
        $e = new UnauthorizedClientException('not allowed');
        self::assertSame('unauthorized_client', $e->getError());
        self::assertSame(400, $e->getHttpStatusCode());
    }

    public function testUnsupportedGrantTypeIs400(): void
    {
        $e = new UnsupportedGrantTypeException('unknown');
        self::assertSame('unsupported_grant_type', $e->getError());
        self::assertSame(400, $e->getHttpStatusCode());
    }

    public function testAccessDeniedIs403(): void
    {
        $e = new AccessDeniedException('denied');
        self::assertSame('access_denied', $e->getError());
        self::assertSame(403, $e->getHttpStatusCode());
    }

    public function testPreviousExceptionChaining(): void
    {
        $prev = new RuntimeException('root');
        $e = new OAuthException('test', 'desc', '', 400, $prev);
        self::assertSame($prev, $e->getPrevious());
    }
}
