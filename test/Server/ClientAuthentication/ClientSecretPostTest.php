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

namespace Horde\OAuth\Test\Server\ClientAuthentication;

use Horde\Http\ServerRequest;
use Horde\OAuth\Server\ClientAuthentication\ClientSecretPost;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ClientSecretPost::class)]
final class ClientSecretPostTest extends TestCase
{
    private ClientSecretPost $auth;

    protected function setUp(): void
    {
        $this->auth = new ClientSecretPost();
    }

    public function testGetMethod(): void
    {
        self::assertSame('client_secret_post', $this->auth->getMethod());
    }

    public function testAuthenticateWithSecret(): void
    {
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody(['client_id' => 'my-client', 'client_secret' => 'my-secret']);
        $result = $this->auth->authenticate($request);
        self::assertSame(['my-client', 'my-secret'], $result);
    }

    public function testAuthenticatePublicClient(): void
    {
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody(['client_id' => 'public-client']);
        $result = $this->auth->authenticate($request);
        self::assertSame('public-client', $result[0]);
        self::assertNull($result[1]);
    }

    public function testAuthenticateNoParsedBody(): void
    {
        $request = new ServerRequest('POST', 'https://example.com/token');
        self::assertNull($this->auth->authenticate($request));
    }

    public function testAuthenticateEmptyClientId(): void
    {
        $request = (new ServerRequest('POST', 'https://example.com/token'))
            ->withParsedBody(['client_id' => '']);
        self::assertNull($this->auth->authenticate($request));
    }
}
