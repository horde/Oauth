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
use Horde\Oauth\Server\ClientAuthentication\ClientSecretBasic;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ClientSecretBasic::class)]
final class ClientSecretBasicTest extends TestCase
{
    private ClientSecretBasic $auth;

    protected function setUp(): void
    {
        $this->auth = new ClientSecretBasic();
    }

    public function testGetMethod(): void
    {
        self::assertSame('client_secret_basic', $this->auth->getMethod());
    }

    public function testAuthenticateValid(): void
    {
        $encoded = base64_encode('my-client:my-secret');
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withHeader('Authorization', "Basic {$encoded}");
        $result = $this->auth->authenticate($request);
        self::assertSame(['my-client', 'my-secret'], $result);
    }

    public function testAuthenticateUrlDecodes(): void
    {
        $encoded = base64_encode(urlencode('client with spaces') . ':' . urlencode('secret:with:colons'));
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withHeader('Authorization', "Basic {$encoded}");
        $result = $this->auth->authenticate($request);
        self::assertSame('client with spaces', $result[0]);
        self::assertSame('secret:with:colons', $result[1]);
    }

    public function testAuthenticateNoHeader(): void
    {
        $request = new ServerRequest('POST', 'https://example.com/token');
        self::assertNull($this->auth->authenticate($request));
    }

    public function testAuthenticateBearerHeader(): void
    {
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withHeader('Authorization', 'Bearer some-token');
        self::assertNull($this->auth->authenticate($request));
    }

    public function testAuthenticateInvalidBase64(): void
    {
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withHeader('Authorization', 'Basic !!!invalid!!!');
        self::assertNull($this->auth->authenticate($request));
    }

    public function testAuthenticateNoColon(): void
    {
        $encoded = base64_encode('nocredentials');
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withHeader('Authorization', "Basic {$encoded}");
        self::assertNull($this->auth->authenticate($request));
    }
}
