<?php

declare(strict_types=1);

/**
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\Test\V10a\Request;

use Horde\OAuth\V10a\Request\AuthorizationHeader;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(AuthorizationHeader::class)]
final class AuthorizationHeaderTest extends TestCase
{
    public function testBuildBasicHeader(): void
    {
        $header = AuthorizationHeader::build([
            'oauth_consumer_key' => 'key123',
            'oauth_nonce' => 'nonce456',
            'oauth_signature' => 'sig789',
        ]);

        self::assertStringStartsWith('OAuth ', $header);
        self::assertStringContainsString('oauth_consumer_key="key123"', $header);
        self::assertStringContainsString('oauth_nonce="nonce456"', $header);
        self::assertStringContainsString('oauth_signature="sig789"', $header);
    }

    public function testBuildWithRealm(): void
    {
        $header = AuthorizationHeader::build(
            ['oauth_consumer_key' => 'key'],
            'Example',
        );

        self::assertStringStartsWith('OAuth realm="Example"', $header);
        self::assertStringContainsString('oauth_consumer_key="key"', $header);
    }

    public function testBuildFiltersNonOauthParams(): void
    {
        $header = AuthorizationHeader::build([
            'oauth_consumer_key' => 'key',
            'non_oauth_param' => 'should-be-excluded',
            'oauth_nonce' => 'nonce',
        ]);

        self::assertStringNotContainsString('non_oauth_param', $header);
        self::assertStringContainsString('oauth_consumer_key', $header);
        self::assertStringContainsString('oauth_nonce', $header);
    }

    public function testBuildEncodesSpecialChars(): void
    {
        $header = AuthorizationHeader::build([
            'oauth_consumer_key' => 'key with spaces',
        ]);

        self::assertStringContainsString('oauth_consumer_key="key%20with%20spaces"', $header);
    }
}
