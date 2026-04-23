<?php

declare(strict_types=1);

/**
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\Test\V10a\Client;

use Horde\OAuth\Exception\OAuthException;
use Horde\OAuth\V10a\Client\Token;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Token::class)]
final class TokenTest extends TestCase
{
    public function testProperties(): void
    {
        $token = new Token('tok-key', 'tok-secret');
        self::assertSame('tok-key', $token->key);
        self::assertSame('tok-secret', $token->secret);
    }

    public function testFromResponseBody(): void
    {
        $body = 'oauth_token=request-key&oauth_token_secret=request-secret&oauth_callback_confirmed=true';
        $token = Token::fromResponseBody($body);
        self::assertSame('request-key', $token->key);
        self::assertSame('request-secret', $token->secret);
    }

    public function testFromResponseBodyThrowsOnMissingFields(): void
    {
        $this->expectException(OAuthException::class);
        Token::fromResponseBody('oauth_token=only-key');
    }

    public function testToQueryString(): void
    {
        $token = new Token('key with spaces', 'secret&special');
        $qs = $token->toQueryString();
        self::assertStringContainsString('oauth_token=key%20with%20spaces', $qs);
        self::assertStringContainsString('oauth_token_secret=secret%26special', $qs);
    }

    public function testRoundTrip(): void
    {
        $original = new Token('abc123', 'xyz789');
        $restored = Token::fromResponseBody($original->toQueryString());
        self::assertSame($original->key, $restored->key);
        self::assertSame($original->secret, $restored->secret);
    }
}
