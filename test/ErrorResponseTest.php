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

namespace Horde\OAuth\Test;

use Horde\Http\ResponseFactory;
use Horde\Http\StreamFactory;
use Horde\OAuth\ErrorResponse;
use Horde\OAuth\Exception\InvalidClientException;
use Horde\OAuth\Exception\OAuthException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ErrorResponse::class)]
final class ErrorResponseTest extends TestCase
{
    public function testToArrayMinimal(): void
    {
        $e = new OAuthException('server_error');
        $arr = ErrorResponse::toArray($e);
        self::assertSame(['error' => 'server_error'], $arr);
    }

    public function testToArrayWithDescriptionAndUri(): void
    {
        $e = new OAuthException('server_error', 'Something broke', 'https://example.com/err');
        $arr = ErrorResponse::toArray($e);
        self::assertSame('server_error', $arr['error']);
        self::assertSame('Something broke', $arr['error_description']);
        self::assertSame('https://example.com/err', $arr['error_uri']);
    }

    public function testToJson(): void
    {
        $e = new InvalidClientException('Unknown client');
        $json = ErrorResponse::toJson($e);
        $decoded = json_decode($json, true);
        self::assertSame('invalid_client', $decoded['error']);
        self::assertSame('Unknown client', $decoded['error_description']);
    }

    public function testToResponse(): void
    {
        $e = new InvalidClientException('Unknown client');
        $response = ErrorResponse::toResponse($e, new ResponseFactory(), new StreamFactory());
        self::assertSame(401, $response->getStatusCode());
        self::assertStringContainsString('application/json', $response->getHeaderLine('Content-Type'));
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));

        $body = json_decode((string) $response->getBody(), true);
        self::assertSame('invalid_client', $body['error']);
    }
}
